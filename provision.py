import logging
import os
import re
import sys
import yaml
from urllib.parse import urlparse

from fire import Fire
from nornir import InitNornir
from nornir.core.task import Task, Result, MultiResult
from nornir_scrapli.tasks import send_command, send_interactive, get_prompt
from nornir_utils.plugins.functions import print_result


def ftp_get_sync(task, ftp_url, local_path, digest=None, vrf=None, ftp_username=None, ftp_password=None):
    platforms = _platform(task)
    act_rsp = next((n['node'] for n in platforms if n['type'].startswith('A9K-RSP') and n['type'].endswith('(Active)')),  None)
    sby_rsp = next((n['node'] for n in platforms if n['type'].startswith('A9K-RSP') and n['type'].endswith('(Standby)')), None)

    task.run(task=ftp_get, ftp_url=ftp_url, local_path=local_path, vrf=vrf, ftp_username=ftp_username, ftp_password=ftp_password)
    if digest is not None:
        task.run(task=md5sum, path=local_path, digest=digest)

    if sby_rsp is not None:
        task.run(task=copy, src_path=local_path, dst_path=local_path, src_location=act_rsp, dst_location=sby_rsp)
        if digest is not None:
            task.run(task=md5sum, path=local_path, location=sby_rsp, digest=digest)

def ftp_get(task, ftp_url, local_path, location=None, digest=None, vrf=None, ftp_username=None, ftp_password=None):
    uri = urlparse(ftp_url)
    if uri.scheme != 'ftp':
        raise Exception(f"Failed to parse URL: {ftp_url}")

    task.run(task=mkdir, path=os.path.dirname(local_path), location=location)
    task.run(task=delete, path=local_path, location=location)

    address = uri.hostname if uri.port is None else f"{uri.hostname}:{uri.port}"
    command = "copy {}: {} vrf {}".format(
            uri.scheme,
            local_path if location is None else f"{local_path} location {location}",
            vrf or 'default')

    events = [
            (command, "]?", False),
            (address, "]?", False),
            (ftp_username or uri.username or "", "password: ", False),
            (ftp_password or uri.password or "", "]?", True),
            (uri.path.strip('/'), "]?", False),
            ("", _prompt(task), False)]

    resp = task.run(task=send_interactive, interact_events=events, timeout_ops=30, severity_level=logging.DEBUG)
    return Result(host=task.host, result=resp.result.result, failed='%Error' in resp.result.result)

def ftp_put(task, ftp_url, local_path, location=None, vrf=None, ftp_username=None, ftp_password=None):
    uri = urlparse(ftp_url)
    if uri.scheme != 'ftp':
        raise Exception(f"Failed to parse URL: {ftp_url}")

    address = uri.hostname if uri.port is None else f"{uri.hostname}:{uri.port}"
    command = "copy {} {}: vrf {}".format(
            local_path if location is None else f"{local_path} location {location}",
            uri.scheme,
            vrf or 'default')

    events = [
            (command, "]?", False),
            (address, "]?", False),
            (ftp_username or uri.username or "", "password: ", False),
            (ftp_password or uri.password or "", "]?", True),
            (uri.path.strip('/'), _prompt(task), False)]

    resp = task.run(task=send_interactive, interact_events=events, timeout_ops=30, severity_level=logging.DEBUG)
    return Result(host=task.host, result=resp.result.result, failed='%Error' in resp.result.result, changed=False)

def copy(task, src_path, dst_path, src_location=None, dst_location=None):
    task.run(task=mkdir, path=os.path.dirname(dst_path), location=dst_location)
    task.run(task=delete, path=dst_path, location=dst_location)

    command = "copy {} {}".format(
            src_path if src_location is None else f"{src_path} location {src_location}",
            dst_path if dst_location is None else f"{dst_path} location {dst_location}")

    events = [
            (command, "]?", False),
            ("", _prompt(task), False)]

    resp = task.run(task=send_interactive, interact_events=events, timeout_ops=30, severity_level=logging.INFO)
    return Result(host=task.host, result=resp.result.result, failed='%Error' in resp.result.result)

def md5sum(task, path, digest, location=None):
    if location is None:
        command = f"sam verify {path} md5 {digest}"
    else:
        command = f"sam verify net/node{location.replace('/', '_')}/{path} md5 {digest}"

    resp = task.run(task=send_command, command=command, severity_level=logging.DEBUG)
    return Result(host=task.host, result=resp.result, failed=not 'Same digest values' in resp.result, changed=False)

def mkdir(task, path, location=None):
    head, tail = os.path.split(path)
    if not head and tail:
        pass
    else:
        task.run(task=mkdir,  path=head, location=location)
        task.run(task=_mkdir, path=path, location=location)

def _mkdir(task, path, location=None):
    command = "dir {}".format(path if location is None else f"{path} location {location}")

    resp = task.run(task=send_command, command=command, severity_level=logging.DEBUG)
    if not 'No such file or directory' in resp.result:
        return Result(host=task.host, result=None, failed=False, changed=False)

    command = "mkdir {}".format(path if location is None else f"{path} location {location}")

    events = [
                (command, "]?", False),
                ("", _prompt(task), False)]

    resp = task.run(task=send_interactive, interact_events=events, severity_level=logging.DEBUG)
    failed = '%Error' in resp.result.result
    return Result(host=task.host, result=resp.result.result, failed=failed, changed=not failed)

def delete(task, path, location=None):
    command = "dir {}".format(path if location is None else f"{path} location {location}")

    resp = task.run(task=send_command, command=command, severity_level=logging.DEBUG)
    if 'No such file or directory' in resp.result:
        return Result(host=task.host, result=None, failed=False, changed=False)

    command = "delete {}".format(path if location is None else f"{path} location {location}")

    events = [
                (command, "[confirm]", False),
                ("", _prompt(task), False)]

    resp = task.run(task=send_interactive, interact_events=events, severity_level=logging.DEBUG)
    failed = '%Error' in resp.result.result
    return Result(host=task.host, result=resp.result.result, failed=failed, changed=not failed)

def rmdir(task, path, location=None):
    command = "rmdir {}".format(path if location is None else f"{path} location {location}")

    events = [
                (command, "]?", False),
                ("", "[confirm]", False),
                ("", _prompt(task), False),
            ]

    resp = task.run(task=send_interactive, interact_events=events, severity_level=logging.DEBUG)
    failed = bool(re.search('%Error', resp.result.result))
    return Result(host=task.host, result=resp.result.result, failed=failed, changed=not failed)

def _platform(task):
    resp = task.run(task=send_command, command='show platform', severity_level=logging.DEBUG)
    return resp.scrapli_response.textfsm_parse_output(template='textfsm/cisco_xr_admin_show_platform.textfsm')

def _prompt(task):
    resp = task.run(task=get_prompt, severity_level=logging.DEBUG)
    return resp.result


class NornirCLI:
    def __init__(self, config='config/config.yml', severity=logging.INFO, host=None):
        self._nr = InitNornir(config_file=config)
        self._severity_level = severity
        if host is not None:
            self._nr = self._nr.filter(name=host)

        if os.environ.get('USERINFO') is not None:
            userinfo = os.environ['USERINFO'].split(':')
            for _, v in self._nr.inventory.hosts.items():
                v.username = userinfo[0]
                v.password = userinfo[1]

    def _exit(self, resp):
        print_result(resp, severity_level=self._severity_level)
        if resp.failed:
            sys.exit(1)

    def ftp_mget(self, config, ftp_username=None, ftp_password=None):
        with open(config) as file:
            for item in yaml.safe_load(file):
                print()
                self.ftp_get(
                        item.get('ftp_url'),
                        item.get('local_path'),
                        digest=item.get('digest'),
                        vrf=item.get('vrf'),
                        ftp_username=ftp_username,
                        ftp_password=ftp_password)

    def ftp_get(self, ftp_url, local_path, digest=None, vrf='default', ftp_username=None, ftp_password=None):
        ftp_username = ftp_username or os.environ.get('FTP_USERNAME')
        ftp_password = ftp_password or os.environ.get('FTP_PASSWORD')
        self._exit(self._nr.run(
            name=f"download from '{ftp_url}' to '{local_path}'...",
            task=ftp_get_sync,
            ftp_url=ftp_url,
            local_path=local_path,
            digest=digest,
            vrf=vrf,
            ftp_username=ftp_username,
            ftp_password=ftp_password))

    def ftp_put(self, ftp_url, local_path, location=None, vrf="default", ftp_username=None, ftp_password=None):
        ftp_username = ftp_username or os.environ.get('FTP_USERNAME')
        ftp_password = ftp_password or os.environ.get('FTP_PASSWORD')
        self._exit(self._nr.run(
            name=f"upload from '{local_path}' to '{ftp_url}'...",
            task=ftp_put,
            ftp_url=ftp_url,
            local_path=local_path,
            location=location,
            vrf=vrf,
            ftp_username=ftp_username,
            ftp_password=ftp_password))

    def copy(self, src_path, dst_path, src_location=None, dst_location=None, digest=None):
        self._exit(self._nr.run(
            name=f"copy from '{src_path}' to '{dst_path}'...",
            task=copy,
            src_path=src_path,
            dst_path=dst_path,
            src_location=src_location,
            dst_location=dst_location,
            digest=digest))

    def md5sum(self, path, digest, location=None):
        self._exit(self._nr.run(
            task=md5sum,
            path=path,
            digest=digest,
            location=location))

    def mkdir(self, path, location=None):
        self._exit(self._nr.run(
            task=mkdir,
            path=path,
            location=location))

    def delete(self, path, location=None):
        self._exit(self._nr.run(
            task=delete,
            path=path,
            location=location))

    def rmdir(self, path, location=None):
        self._exit(self._nr.run(
            task=rmdir,
            path=path,
            location=location))

if __name__ == '__main__':
    Fire(NornirCLI)
