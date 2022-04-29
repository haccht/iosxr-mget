import logging
import os
import re
import sys
import yaml
from urllib.parse import urlparse

from fire import Fire
from nornir import InitNornir
from nornir.core.task import Result
from nornir_scrapli.tasks import send_command, send_interactive, get_prompt
from nornir_utils.plugins.functions import print_result


def download(task, url, local_path, digest=None, vrf=None, ftp_username=None, ftp_password=None, force=False):
    platforms = _platform(task)
    act_rsp = next((n['node'] for n in platforms if n['type'].startswith('A9K-RSP') and n['type'].endswith('(Active)')),  None)
    sby_rsp = next((n['node'] for n in platforms if n['type'].startswith('A9K-RSP') and n['type'].endswith('(Standby)')), None)

    uri = urlparse(url)
    if uri.scheme == 'ftp':
        task.run(task=_ftp_get,  uri=uri, local_path=local_path, vrf=vrf, ftp_username=ftp_username, ftp_password=ftp_password, force=force)
    elif uri.scheme == 'tftp':
        task.run(task=_tftp_get, uri=uri, local_path=local_path, vrf=vrf, force=force)
    else:
       raise Exception(f"Failed to parse URL: {url}")

    if digest is not None:
        task.run(task=md5sum, local_path=local_path, digest=digest)

    if act_rsp is not None and sby_rsp is not None:
        task.run(task=copy, src_path=local_path, dst_path=local_path, src_location=act_rsp, dst_location=sby_rsp, force=force)

        if digest is not None:
            task.run(task=md5sum, local_path=local_path, location=sby_rsp, digest=digest)

def _ftp_get(task, uri, local_path, location=None, vrf=None, ftp_username=None, ftp_password=None, force=False):
    if not _path_overwrite(task, local_path=local_path, location=location, force=force):
        return Result(host=task.host, result=None, failed=False, changed=False)

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

    resp = task.run(task=send_interactive, interact_events=events, timeout_ops=0, severity_level=logging.DEBUG)
    return Result(host=task.host, result=resp.result.result, failed='%Error' in resp.result.result)

def _tftp_get(task, uri, local_path, location=None, vrf=None, force=False):
    if not _path_overwrite(task, local_path=local_path, location=location, force=force):
        return Result(host=task.host, result=None, failed=False, changed=False)

    address = uri.hostname if uri.port is None else f"{uri.hostname}:{uri.port}"
    command = "copy {}: {} vrf {}".format(
        uri.scheme,
        local_path if location is None else f"{local_path} location {location}",
        vrf or 'default')
    events = [
        (command, "]?", False),
        (address, "]?", False),
        (uri.path.strip('/'), "]?", False),
        ("", _prompt(task), False)]

    resp = task.run(task=send_interactive, interact_events=events, timeout_ops=0, severity_level=logging.DEBUG)
    return Result(host=task.host, result=resp.result.result, failed='%Error' in resp.result.result)

def upload(task, url, local_path, digest=None, vrf=None, ftp_username=None, ftp_password=None):
    uri = urlparse(url)
    if uri.scheme == 'ftp':
        task.run(task=_ftp_put,  uri=uri, local_path=local_path, vrf=None, ftp_username=None, ftp_password=None)
    elif uri.scheme == 'tftp':
        task.run(task=_tftp_put, uri=uri, local_path=local_path, vrf=None)
    else:
       raise Exception(f"Failed to parse URL: {url}")

def _ftp_put(task, uri, local_path, location=None, vrf=None, ftp_username=None, ftp_password=None):
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

    resp = task.run(task=send_interactive, interact_events=events, timeout_ops=0, severity_level=logging.DEBUG)
    return Result(host=task.host, result=resp.result.result, failed='%Error' in resp.result.result, changed=False)

def _tftp_put(task, uri, local_path, location=None, vrf=None):
    address = uri.hostname if uri.port is None else f"{uri.hostname}:{uri.port}"
    command = "copy {} {}: vrf {}".format(
        local_path if location is None else f"{local_path} location {location}",
        uri.scheme,
        vrf or 'default')
    events = [
        (command, "]?", False),
        (address, "]?", False),
        (uri.path.strip('/'), _prompt(task), False)]

    resp = task.run(task=send_interactive, interact_events=events, timeout_ops=0, severity_level=logging.DEBUG)
    return Result(host=task.host, result=resp.result.result, failed='%Error' in resp.result.result, changed=False)

def copy(task, src_path, dst_path, src_location=None, dst_location=None, override=False, force=False):
    if not _path_overwrite(task, local_path=dst_path, location=dst_location, force=force):
        return Result(host=task.host, result=None, failed=False, changed=False)

    command = "copy {} {}".format(
        src_path if src_location is None else f"{src_path} location {src_location}",
        dst_path if dst_location is None else f"{dst_path} location {dst_location}")
    events = [
        (command, "]?", False),
        ("", _prompt(task), False)]

    resp = task.run(task=send_interactive, interact_events=events, timeout_ops=0, severity_level=logging.INFO)
    return Result(host=task.host, result=resp.result.result, failed='%Error' in resp.result.result)

def md5sum(task, local_path, digest, location=None):
    if location is None:
        command = f"sam verify {local_path} md5 {digest}"
    else:
        command = f"sam verify net/node{location.replace('/', '_')}/{local_path} md5 {digest}"

    resp = task.run(task=send_command, command=command, timeout_ops=0, severity_level=logging.DEBUG)
    return Result(host=task.host, result=resp.result, failed=not 'Same digest values' in resp.result, changed=False)

def mkdir(task, local_path, location=None):
    head, tail = os.path.split(local_path)
    if not head and tail:
        pass
    else:
        task.run(task=mkdir,  local_path=head,       location=location)
        task.run(task=_mkdir, local_path=local_path, location=location)

def _mkdir(task, local_path, location=None):
    if _path_exist(task, local_path=local_path, location=location):
        return Result(host=task.host, result=None, failed=False, changed=False)

    command = "mkdir {}".format(local_path if location is None else f"{local_path} location {location}")
    events = [
        (command, "]?", False),
        ("", _prompt(task), False)]

    resp = task.run(task=send_interactive, interact_events=events, severity_level=logging.DEBUG)
    return Result(host=task.host, result=resp.result.result, failed='%Error' in resp.result.result)

def delete(task, local_path, location=None):
    if not _path_exist(task, local_path=local_path, location=location):
        return Result(host=task.host, result=None, failed=False, changed=False)

    command = "delete {}".format(local_path if location is None else f"{local_path} location {location}")
    events = [
        (command, "[confirm]", False),
        ("", _prompt(task), False)]

    resp = task.run(task=send_interactive, interact_events=events, severity_level=logging.DEBUG)
    return Result(host=task.host, result=resp.result.result, failed='%Error' in resp.result.result)

def rmdir(task, local_path, location=None):
    command = "rmdir {}".format(local_path if location is None else f"{local_path} location {location}")
    events = [
        (command, "]?", False),
        ("", "[confirm]", False),
        ("", _prompt(task), False)]

    resp = task.run(task=send_interactive, interact_events=events, severity_level=logging.DEBUG)
    return Result(host=task.host, result=resp.result.result, failed='%Error' in resp.result.result)

def _prompt(task):
    resp = task.run(task=get_prompt, severity_level=logging.DEBUG)
    return resp.result

def _platform(task):
    resp = task.run(task=send_command, command='show platform', severity_level=logging.DEBUG)
    return resp.scrapli_response.textfsm_parse_output(template='textfsm/cisco_xr_admin_show_platform.textfsm')

def _path_exist(task, local_path, location=None):
    command = "dir {}".format(local_path if location is None else f"{local_path} location {location}")
    resp = task.run(task=send_command, command=command, severity_level=logging.DEBUG)
    return not ('No such file or directory' in resp.result or 'No such node' in resp.result)

def _path_overwrite(task, local_path, location=None, force=False):
    if _path_exist(task, local_path=local_path, location=location):
        if force:
            task.run(task=delete, local_path=local_path, location=location)
        else:
            return False
    else:
        task.run(task=mkdir, local_path=os.path.dirname(local_path), location=location)
    return True


class NornirCLI:
    def __init__(self, config='config/config.yml', severity=logging.INFO, jobs=10, host=None):
        self._nr = InitNornir(
            config_file=config,
            runner={
              "plugin": "threaded",
              "options": { "num_workers": jobs }
            })
        self._severity_level = severity

        if host is not None:
            self._nr = self._nr.filter(name=host)

        if os.environ.get('USERINFO') is not None:
            userinfo = os.environ['USERINFO'].split(':')
            for _, v in self._nr.inventory.hosts.items():
                v.username = userinfo[0]
                v.password = userinfo[1]

    def _W(self, result, display_result=True):
        if display_result:
            print_result(result, severity_level=self._severity_level)
        if result.failed:
            print(f"Failed at {list(result.failed_hosts.keys())}")
            sys.exit(1)

    def mget(self, config_file, ftp_username=None, ftp_password=None, force=False):
        def _mget(task, items):
            for item in items:
                url = item.get('url')
                local_path = item.get('local_path')
                ftp_username = item.get('ftp_username') or os.environ.get('FTP_USERNAME')
                ftp_password = item.get('ftp_password') or os.environ.get('FTP_PASSWORD')
                resp = task.run(
                    name=f"download from '{url}' to '{local_path}'...",
                    task=download,
                    url=url,
                    local_path=local_path,
                    digest=item.get('digest'),
                    vrf=item.get('vrf'),
                    ftp_username=ftp_username,
                    ftp_password=ftp_password,
                    force=force)
                print_result(resp, severity_level=self._severity_level)

        with open(config_file) as file:
            self._W(self._nr.run(task=_mget, items=yaml.safe_load(file)), display_result=False)

    def get(self, url, local_path, digest=None, vrf='default', ftp_username=None, ftp_password=None, force=False):
        ftp_username = ftp_username or os.environ.get('FTP_USERNAME')
        ftp_password = ftp_password or os.environ.get('FTP_PASSWORD')
        self._W(self._nr.run(
            name=f"download from '{url}' to '{local_path}'...",
            task=download,
            url=url,
            local_path=local_path,
            digest=digest,
            vrf=vrf,
            ftp_username=ftp_username,
            ftp_password=ftp_password,
            force=force))

    def put(self, url, local_path, location=None, vrf="default", ftp_username=None, ftp_password=None):
        ftp_username = ftp_username or os.environ.get('FTP_USERNAME')
        ftp_password = ftp_password or os.environ.get('FTP_PASSWORD')
        self._W(self._nr.run(
            name=f"upload from '{local_path}' to '{url}'...",
            task=upload,
            url=url,
            local_path=local_path,
            location=location,
            vrf=vrf,
            ftp_username=ftp_username,
            ftp_password=ftp_password))

    def copy(self, src_path, dst_path, src_location=None, dst_location=None, digest=None, force=False):
        self._W(self._nr.run(
            name=f"copy from '{src_path}' to '{dst_path}'...",
            task=copy,
            src_path=src_path,
            dst_path=dst_path,
            src_location=src_location,
            dst_location=dst_location,
            digest=digest,
            force=force))

    def md5sum(self, path, digest, location=None):
        self._W(self._nr.run(
            task=md5sum,
            local_path=path,
            digest=digest,
            location=location))

    def mkdir(self, path, location=None):
        self._W(self._nr.run(
            task=mkdir,
            local_path=path,
            location=location))

    def delete(self, path, location=None):
        self._W(self._nr.run(
            task=delete,
            local_path=path,
            location=location))

    def rmdir(self, path, location=None):
        self._W(self._nr.run(
            task=rmdir,
            local_path=path,
            location=location))

if __name__ == '__main__':
    Fire(NornirCLI)
