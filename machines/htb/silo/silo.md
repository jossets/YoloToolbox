# silo

- Windows Server 2008 R2
- IIS 8.5
- Oracle TNS listener 11.2.0.2.0

- Bruteforce Oracle password
- Then use odat to read and upload files...

Not tested


## Walkthrough
- https://v3ded.github.io/ctf/htb-silo.html
- https://medium.com/@DRX_Sicher/walkthrough-silo-hackthebox-929f7f0a7431
- https://medium.com/@sathish__kumar/hackthebox-silo-writeup-5fe92ac04bb5
- https://0xdf.gitlab.io/2018/08/04/htb-silo.html



## Nmap

````
nmap -sC -sV -oA nmap/initial 10.10.10.82

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: IIS Windows Server
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn?
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  oracle-tns   Oracle TNS listener (requires service name)                                                                                 49161/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submi
t.cgi?new-service :
SF-Port139-TCP:V=7.70%I=7%D=4/21%Time=5ADBEBEB%P=x86_64-pc-linux-gnu%r(Get
SF:Request,5,"\x83\0\0\x01\x8f");
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb-security-mode:
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: supported
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2018-04-21 21:58:51
|_  start_date: 2018-04-21 15:47:47
````


## Oracle

### Install driver ??

- Install Oracle drivers : https://v3ded.github.io/ctf/htb-silo.html


Metasploit:
    -https://github.com/rapid7/metasploit-framework/wiki/How-to-get-Oracle-Support-working-with-Kali-Linux
    -https://blog.zsec.uk/msforacle/
ODAT:
    -https://github.com/quentinhardy/odat/blob/master/README.md (scroll down to the install section) 

Please find here the link of the software:

https://github.com/quentinhardy/odat

And here, the standalone version:

https://github.com/quentinhardy/odat/releases/



    
    
    
