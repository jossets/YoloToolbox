# HTB - Joker  10.10.10.21



## Usefull
Tcp
- nmap -sC -sV -A SERVER
- nmap -sC -sV -A SERVER -p-
UDP
- nmap -sU -sV -A SERVER
- snmpwalk -c public -v1 SERVER
- snmpwalk -v 2c -c public SERVER
- snmpwalk -v2c -c public SERVER 1.3.6.1.2.1.4.34.1.3

HTTP
- http://SERVER/robots.txt
- dirb http://SERVER
- /opt/gobuster/gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://SERVER  -l -x html,php,js,txt
- wkhtmltoimage url pngfile 

Bind : 53
- /etc/hosts
- dig axfr @SERVER cronos.htb

SMB : 
- enum4linux SERVER  
- enum4linux SERVER -U 

## Nmap
```
nmap -sC -sV -A 10.10.10.21
```

