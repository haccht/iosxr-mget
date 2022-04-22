# iosxr-ftp-mget
Cisco IOS-XR装置にFTPサーバーからファイルをダウンロードするためのプロビジョニングツール。

## 使い方

環境構築
```
$ git clone https://github.com/haccht/iosxr-ftp-mget.git
$ cd iosxr-ftp-mget
$ pipenv --python 3.9
$ pipenv install
```

対象機器一覧を`config/hosts.yml`ファイルに記載する
```
$ cat << EOL > config/hosts.yml
iosxrv1:
    hostname: 192.168.1.1
iosxrv2:
    hostname: 192.168.1.2
EOL
```

ファイルをひとつだけ取得する方法  
RSP冗長構成の場合は冗長側RSPにもファイルを自動コピーする
```
$ export USERINFO=<login_username:<login_password> FTP_USERNAME=<ftp_username> FTP_PASSWORD=<ftp_password>
$ pipenv run python provision.py ftp_get ftp://<address>/path/to/file usb:/path/to/file
```

複数ファイルを一括取得する方法  
まず取得ファイルをまとめた`mget.yml`ファイルを用意する  
`digest`を指定すると取得したファイルのmd5ハッシュ値の整合性チェックを併せて行う
```
$ cat << EOL > mget.yml
- ftp_url: ftp://<address>/path/to/file1
  local_path: usb:/path/to/file1
  digest: xxxxxxxxxxxx
- ftp_url: ftp://<address>/path/to/file2
  local_path: usb:/path/to/file2
  digest: yyyyyyyyyyyy
EOL
```

ツール起動し一括取得する。エラーが発生した場合は途中で停止する
```
$ export USERINFO=<login_username:<login_password> FTP_USERNAME=<ftp_username> FTP_PASSWORD=<ftp_password>
$ pipenv run python provision.py ftp_mget mget.yml
```
