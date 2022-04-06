---
title: TryHackMe CC - Pen Testing write-up
date: 2022-04-06 23:43:30 +1300
categories: [IT, CyberSec]
tags: [write-up]
---

### task 1

### task 2
Pretty easy, so I am only listing notable questions
$ sudo nmap -p80 -sVC 10.10.65.59

### task 3
All answers can be found in netcat man page
$ man nc

### task 4
Mostly just reading gobuster man page
$ gobuster help ~
#### Q: What is the name of the hidden directory
$ gobuster dir -u 10.10.236.179 -w /usr/share/wordlists/rockyou.txt

#### Q: What is the name of the hidden file with the extension xxa
$ gobuster dir -u 10.10.236.179 -w /usr/share/wordlists/rockyou.txt -x xxa

### task 5
