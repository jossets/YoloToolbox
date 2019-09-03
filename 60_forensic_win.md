# Forensic Windows



## Windows Memdump : extract SAM

### install Volatility
````
https://www.volatilityfoundation.org/releases
````

### Volatility profile


````
$ volatility kdbgscan -f SILO-20180105-221806.dmp
**************************************************
Instantiating KDBG using: Unnamed AS Win2012R2x64_18340 (6.3.9601 64bit)
Offset (V)                    : 0xf80078520a30
Offset (P)                    : 0x2320a30
KdCopyDataBlock (V)           : 0xf8007845f9b0
Block encoded                 : Yes
Wait never                    : 0xd08e8400bd4a143a
Wait always                   : 0x17a949efd11db80
KDBG owner tag check          : True
Profile suggestion (KDBGHeader): Win2012R2x64_18340
Version64                     : 0xf80078520d90 (Major: 15, Minor: 9600)
Service Pack (CmNtCSDVersion) : 0
Build string (NtBuildLab)     : 9600.16384.amd64fre.winblue_rtm.
PsActiveProcessHead           : 0xfffff80078537700 (51 processes)
PsLoadedModuleList            : 0xfffff800785519b0 (148 modules)
KernelBase                    : 0xfffff8007828a000 (Matches MZ: True)
Major (OptionalHeader)        : 6
Minor (OptionalHeader)        : 3
KPCR                          : 0xfffff8007857b000 (CPU 0)
KPCR                          : 0xffffd000207e8000 (CPU 1)

**************************************************
````
=> Profile suggestion: Win2012R2x64_18340


### Volatility Hivelist
````
root@kali:~/hackthebox/silo-10.10.10.82# volatility -f SILO-20180105-221806.dmp --profile Win2012R2x64 hivelist
Volatility Foundation Volatility Framework 2.6
Virtual            Physical           Name
------------------ ------------------ ----
0xffffc0000100a000 0x000000000d40e000 \??\C:\Users\Administrator\AppData\Local\Microsoft\Windows\UsrClass.dat
0xffffc000011fb000 0x0000000034570000 \SystemRoot\System32\config\DRIVERS
0xffffc00001600000 0x000000003327b000 \??\C:\Windows\AppCompat\Programs\Amcache.hve
0xffffc0000001e000 0x0000000000b65000 [no name]
0xffffc00000028000 0x0000000000a70000 \REGISTRY\MACHINE\SYSTEM
0xffffc00000052000 0x000000001a25b000 \REGISTRY\MACHINE\HARDWARE
0xffffc000004de000 0x0000000024cf8000 \Device\HarddiskVolume1\Boot\BCD
0xffffc00000103000 0x000000003205d000 \SystemRoot\System32\Config\SOFTWARE
0xffffc00002c43000 0x0000000028ecb000 \SystemRoot\System32\Config\DEFAULT
0xffffc000061a3000 0x0000000027532000 \SystemRoot\System32\Config\SECURITY
0xffffc00000619000 0x0000000026cc5000 \SystemRoot\System32\Config\SAM
0xffffc0000060d000 0x0000000026c93000 \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT
0xffffc000006cf000 0x000000002688f000 \SystemRoot\System32\Config\BBI
0xffffc000007e7000 0x00000000259a8000 \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT
0xffffc00000fed000 0x000000000d67f000 \??\C:\Users\Administrator\ntuser.dat
````
- 0xffffc00000028000 0x0000000000a70000 \REGISTRY\MACHINE\SYSTEM
- 0xffffc00000619000 0x0000000026cc5000 \SystemRoot\System32\Config\SAM

### Volatility hashdump
````
root@kali:~/hackthebox/silo-10.10.10.82# volatility -f SILO-20180105-221806.dmp --profile Win2012R2x64 hashdump -y 0xffffc00000028000 -s 0xffffc00000619000
Volatility Foundation Volatility Framework 2.6
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Phineas:1002:aad3b435b51404eeaad3b435b51404ee:8eacdd67b77749e65d3b3d5c110b0969:::
````

