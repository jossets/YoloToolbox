# My Toolbox for CTF


## Network enum
[net enum](10_net_enum.md)



## Privilege escalation

```
>systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600

C:\Windows\system32> hostname
b33f

C:\Windows\system32> echo %username%
user1
```
more => http://www.fuzzysecurity.com/tutorials/16.html
