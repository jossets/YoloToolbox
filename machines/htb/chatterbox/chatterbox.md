# HTB - Chatterbox  10.10.10.74






Note: This box is based on AChat v0.150 beta7 which crash after exploit...



## Walkthrough 

- https://0xdf.gitlab.io/2018/06/18/htb-chatterbox.html
- https://www.absolomb.com/2018-06-16-HackTheBox-Chatterbox/

## Nmap


Unsuccesfull nmaps...


Supposed to find ports
```
# nmap -sV -p- 10.10.10.74 -T4

Starting Nmap 7.60 ( https://nmap.org ) at 2018-03-02 15:16 EST
Nmap scan report for 10.10.10.74
Host is up (0.050s latency).

PORT     STATE SERVICE VERSION
9255/tcp open  http    AChat chat system httpd
9256/tcp open  achat   AChat chat system
```

but see nothing...


https://www.exploit-db.com/exploits/36025

