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
## 80: HTTP

### Nikto
    Identify server
    https://github.com/sullo/nikto
    # nikto -host xxx

### Gobuster
    Find hidden files & dir
    https://github.com/OJ/gobuster
    # gobuster -u http://172.16.27.142/ -w /opt/SecLists/Discovery/Web-Content/common.txt -x html,php -s 200,301,401,403
    # gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://172.16.27.142  -l -x html,php,js,txt


### Dirbuster
    Find hidden files & dir
    https://github.com/digination/dirbuster-ng
    # dirb http://10.10.10.93/aspnet_client/system_web/ fuzz.txt -r
    # dirb http://10.10.10.93/ /usr/share/wordlists/dirb/common.txt -r


#### Web server Directories
    https://github.com/digination/dirbuster-ng/tree/master/wordlists
    IIS : https://github.com/digination/dirbuster-ng/blob/master/wordlists/vulns/iis.txt
    Kali Dictionaries:
    /usr/share/wordlists/dirb/common.txt
    /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt


=============================================================

## Wordpress
### Wpscan
    # wpscan -u http://raven.local/wordpress -e
    Note : mysql Credentials location: /var/www/html/wordpress/wp-config.php

=============================================================

## Glassfish

=============================================================

## Php

=============================================================

## Ruby on Rail

=============================================================
## 21: Ftp
    Try password list
    # hydra -t 1 -l admin -P /root/Desktop/password.lst -vV 192.168.1.1 ftp
    Check anonymous access
    # ./msfconsole -x “use auxiliary/scanner/ftp/anonymous; set ConnectTimeout=1; set FTPTimeout=1; set RHOSTS=xxx.xxx.xxx.0/19; run”
    Note : for large network : set variable THREADS increase perf
    

=============================================================
## 22: Ssh
### Hydra
    # hydra -l root -e nsr -V -o hydra.log -t8 -f ssh://raven.local


=============================================================
## 23: Telnet
    # nmap -p 23 --script telnet-brute --script-args userdb=users.lst,passdb=/usr/share/john/password.lst,telnet-brute.timeout=8s <target>




