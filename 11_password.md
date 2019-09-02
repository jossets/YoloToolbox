# Default credentials


## password
Kali Dictionaries
- /usr/share/john/password.lst
- /usr/share/dirb/wordlists/big.txt
- /usr/share/wfuzz/wordlist/general/big.txt
- /usr/share/wordlists/rockyou.txt             (unzip it before use)
- /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt


## Listes
SecLists: wget https://github.com/danielmiessler/SecLists/archive/master.zip


## ftp default passwd

````
USER anonymous
````


## Apache Tomcat Default Credentials

|Username     |Password  |
|-------------|----------|
|admin        |password  |
|admin        |<blank>   |
|admin        |Password1 |
|admin        |password1 |
|admin        |admin     |
|admin        |tomcat    |
|both         |tomcat    |
|manager      |manager   |
|role1        |role1     |
|role1        |tomcat    |
|role         |changethis|
|root         |Password1 |
|root         |changethis|
|root         |password  |
|root         |password1 |
|root         |r00t      |
|root         |root      |
|root         |toor      |
|tomcat       |tomcat    |
|tomcat       |s3cret    |
|tomcat       |password1 |
|tomcat       |password  |
|tomcat       |<blank>   |
|tomcat       |admin     |
|tomcat       |changethis|

## PostgreSQL

|Username     |Password     |
|-------------|-------------|
|postgres     |postgres     |
|postgres     |password     |
|postgres     |admin        |
|admin        |admin        |
|admin        |password     |


## Oracle

|  Username   |   Password      |
|-------------|-----------------|
|SYSTEM       |MANAGER          |
|SCOTT        |TIGER            |
|SYS          |CHANGE_ON_INSTALL|
|OUTLN        |OUTLN            |
|DBSNMP       |DBSNMP           |
|CTXSYS       |CTXSYS           |
|MDSYS        |MDSYS            |


## hash-identifier
    hash-identifier xxxxxx

## Unshadow /etc/passwd+/etc/shadow

    unshadow password_file shadow_file > new_password_list

## John 

    john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA256 password_list

## Misconfigured AD
    net use z: \\(target_hostname)\SYSVOL
    dir /s Groups.xml
    type Z:\local.domain\Policies\{84583021-C460-486C-83E1- FA1EC8CA84FC}\Machine\Preferences\Groups\Groups.xml
    gpp-decrypt SvtusBQWJgAFrFPTyPH9clizXPQBDqDDGzlSDxKogcz, password will be outputted


## SAM Cracking: WCE32/WCE64
    About: wce32.exe (wce64.exe) can be used to attempt cracking of user passwords in memory
    wce32.exe -w 
    wce64.exe -w

## SAM Cracking: FGdump
    FGdump.exe can be used to crack local SAM hashes in memory. 
    The program uses the IPC$ share to connect and additionally attempts to disable antivirus that may be running on the host
    fgdump.exe, then "type 127.0.0.1.pwdump" to list found pwd

## SAM Cracking: PWdump
    About: PWdump.exe can be used to crack local SAM hashes in memory. Does not have the added bonus like FGdump of disabling antivirus. This will need to be done prior to running the program
    Usage: pwdump.exe (host)
    pwdump.exe
    pwdump.exe 127.0.0.1

## Keepass
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


## Online hash crackers:

### Hashkiller (Windows/NTLM):
    https://hashkiller.co.uk/ntlm-decrypter.aspx

### Crackstation (MD5):
    https://crackstation.net

### Offensive security (MD5):

    http://cracker.offensive-security.com

### RDCMan - Decrypt Microsoft Remote Desktop Manager passwords (RDCman)
    Open the .rdg file with a text editor and copy in the password section
    
