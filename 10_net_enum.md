# Network enum


## Discover Hosts
### IP: Netdiscover
    # netdiscover -r 192.168.206.0/24


### Netbios: Nbtscan
    Scan for Netbios Hosts
    Url: http://www.inetcat.org/software/nbtscan.html
    # nbtscan 192.168.206.0/24




=============================================================
## Port scanner
### Nmap
    # nmap -sV -A  192.168.206.23
    # nmap -sV -sC -p- 10.10.10.93
        -sV : Attempts to determine the version of the service running on port
        -sC : Scan with default NSE scripts. Considered useful for discovery and safe
        -A   : Enables OS detection, version detection, script scanning, and traceroute
        -p-  : Port scan all ports
        -oN nmap.log : output normal file
          

### Unicornscan 
    unicorn

### One Two Punch
    Use unicorn to scan open ports, then nmap to identify services
    https://github.com/superkojiman/onetwopunch


=============================================================
## 21: Ftp

Check anonymous access
````
anonymous       anonymous
````

Use nmap script
````
nmap --script=ftp-anon.nse 10.10.10.9
````

Hydra password list
````
# hydra -t 1 -l admin -P /root/Desktop/password.lst -vV 192.168.1.1 ftp
````

Msfconsole scanner
````
# ./msfconsole -x “use auxiliary/scanner/ftp/anonymous; set ConnectTimeout=1; set FTPTimeout=1; set RHOSTS=xxx.xxx.xxx.0/19; run”
Note : for large network : set variable THREADS increase perf
````

Msfconsole password list
````
> use auxiliary/scanner/ftp/ftp_login
````    

    

=============================================================
## 22: Ssh
### Hydra
    # hydra -l root -e nsr -V -o hydra.log -t8 -f ssh://raven.local
    hydra –l (found_name) –P password.lst 192.168.168.168 ssh
    hydra -L username_list.txt -P password_list.txt 192.168.168.168 ssh -t 4
=============================================================
## 23: Telnet
    # nmap -p 23 --script telnet-brute --script-args userdb=users.lst,passdb=/usr/share/john/password.lst,telnet-brute.timeout=8s <target>


=============================================================
## 80: HTTP

### Magic files
    /robots.txt
    Comments in the HTML source code.


### Nman Enum script
    $ nmap -script http-enum.nse -p80 192.168.168.168

### Dirbuster
    Find hidden files & dir
    https://github.com/digination/dirbuster-ng
    # dirb http://10.10.10.93
    # dirb http://10.10.10.93/aspnet_client/system_web/ fuzz.txt -r                        : -r dont search recurvively
    # dirb http://10.10.10.93/ /usr/share/wordlists/dirb/common.txt -r
    # dirb http://10.10.10.24/ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt



### Nikto
    Identify server
    https://github.com/sullo/nikto
    $ nikto -host xxx
    $ nikto -h 192.168.168.168 -p (port)

### Gobuster
    Find hidden files & dir
    https://github.com/OJ/gobuster
    wget https://github.com/OJ/gobuster/releases/download/v3.0.1/gobuster-linux-amd64.7z
    ./gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://172.16.27.142  -l -x html,php,js,txt

    # gobuster -u http://172.16.27.142/ -w /opt/SecLists/Discovery/Web-Content/common.txt -x html,php -s 200,301,401,403
    # ./gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://172.16.27.142  -l -x html,php,js,txt
    # gobuster -u http://192.168.168.168/ -w /usr/share/seclists/Discovery/Web_Content/common.txt -s 200,204,301,302,307,403,500 –e

### Curl
    curl http://192.168.168.168/admin.php?action=users&login=0

    
### Web server Common Directories
    https://github.com/digination/dirbuster-ng/tree/master/wordlists
    IIS : https://github.com/digination/dirbuster-ng/blob/master/wordlists/vulns/iis.txt
    Kali Dictionaries:
    /usr/share/wordlists/dirb/common.txt
    /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

### Cewl
    Get word list from sweb site
    $ cewl http://192.168.168.168/index.html -m 2 -w cewl.lst



=============================================================

## Wordpress
### Wpscan
    # wpscan -u http://raven.local/wordpress -e
    Note : mysql Credentials location: /var/www/html/wordpress/wp-config.php

=============================================================

## Glassfish

=============================================================

## IIS Versions

IIS 1.0	Windows NT 3.51
IIS 2.0	Windows NT 4.0
IIS 3.0	Windows NT 4.0 SP3
IIS 4.0	Windows NT 4.0 Options Pack
IIS 5.0	Windows 2000
IIS 5.1	Windows XP Professional x32
IIS 6.0	Windows Server 2003
IIS 6.0	Windows Server 2003 R2
IIS 6.0	Windows XP Professional x64
IIS 7.0	Windows Vista
IIS 7.0	Windows 7
IIS 7.0	Windows Server 2008
IIS 7.5	Windows Server 2008 R2


=============================================================

## WebDAV

Web Distributed Authoring and Versioning (WebDAV) is an extension of the Hypertext Transfer Protocol (HTTP) that allows clients to perform remote Web content authoring operations.
    Apache HTTP Server provides WebDAV modules based on both davfs and Apache Subversion (svn).
    Microsoft's IIS has a WebDAV module.
    Nginx has a very limited optional WebDAV module[4] and a third-party module[5]
    SabreDAV is a PHP application that can be used on Apache or Nginx in lieu of their bundled modules
    ownCloud is a cloud storage PHP application which offers full WebDAV support[6]
    Nextcloud is a fork of ownCloud, and therefore also offers full WebDAV support[7]
    lighttpd has an optional WebDAV module[8]
    Caddy has an optional WebDAV module[9]

### Davtest
    Testing tool for WebDAV servers
    $ davtest –url http://(target IP) – will display what is executable


### Cadaver
    A command-line WebDAV client for Unix. 
    cadaver http://(target IP), then run “ls” to list directories found


=============================================================

## Drupal
### Droopescan
    /opt/droopescan/droopescan scan drupal -u http://10.10.10.9

=============================================================

## Crawl php server
    python3 /opt/dirsearch/dirsearch.py -u http://10.10.10.9/ -e php -x 403,404 -t 50
    Look for : 
    phpinfo.php
    /phpliteadmin
    /dashboard
    /admin
    /admin.php
    /login
    /login.php

=============================================================

## Ruby on Rail





=============================================================
## 137-139-445 : NetBios/Smb

### Nmap scripts
    nmap --script smb-vuln*.nse
    nmap 192.168.168.168 --script=smb-vuln*.nse location: /usr/share/nmap/scripts/smb-vuln*.nse


### Enum4Linux
    enum4linux 192.168.168.168  
    enum4linux 192.168.168.168 -U   : grab userlist

### Smbclient
    lists smb type (often displaying samba version) and various shares
    smbclient -N -L 192.168.168.168 - 

### Accesschk
    Attempts to connect to $IPC or $ADMIN shares
    accesschk -v -t (target IP) -u user -P /usr/share/dirb/wordlists/common.txt 

### Mount linux share
    rdesktop -u username -p password -r disk:share=/home//Desktop 192.168.168.168

=============================================================
## 161 : SNMP (UDP)

### Snmpwalk
    snmpwalk -c public -v1 192.168.168.168



=============================================================
## 3000 : Node JS

### xxx



=============================================================
## 3306 : MySQL

### sqsh
    $ apt-get install sqsh freetds-bin freetds-common freetds-dev
    Add to the bottom of freetds.conf:
        [hostname] host = 192.168.168.169
        port = 2600
        tds version = 8.0
    edit ~/.sqshrc:
        \set username=sa
        \set password=password
        \set style=vert
    $ sqsh -S hostname
    select sys_exec('/bin/bash');
    (escalation: bash -p or sudo su)
