#  RopEmporium : callme

## TLDR


Call 3 functions with 3 int64 parameters from external library (POT table)
- get gadgets 
- Get fcts addr 
- bufferoffset + gadget(pop ;ret) + string addr + function1 addr 
               + gadget(pop ;ret) + string addr + function2 addr 
               + gadget(pop ;ret) + string addr + function3 addr 


## Checksec 

```
$ checksec callme
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
NX -> rop 


## Buffer size

```gdb
gdb-peda$ pattern_create 200 pattern
gdb-peda$ r < pattern
gdb-peda$ pattern offset AA0AAFAA
AA0AAFAA found at offset: 40
```
offset => 40 bytes


## function address 


Il faut faire la différence entre les adresses des fct, et les appels aux fct

```
$ gdb callme
gdb-peda$ info functions

0x00000000004006f0  callme_three@plt
0x0000000000400720  callme_one@plt
0x0000000000400740  callme_two@plt
0x0000000000400847  main
0x0000000000400898  pwnme
0x00000000004008f2  usefulFunction
0x000000000040093c  usefulGadgets
```


Les functions sont là, cherchons un appel dans le code 
```
$ objdump -d callme | grep call
  400905:       e8 e6 fd ff ff          callq  4006f0 <callme_three@plt>
  400919:       e8 22 fe ff ff          callq  400740 <callme_two@plt>
  40092d:       e8 ee fd ff ff          callq  400720 <callme_one@plt>
  ```
Ca ne va pas marcher, ces fct utilisent pas les bonnes conventions d'appel:
> incorrect calls to these functions made in the binary, they're there to ensure these functions get linked.



```
$ rabin2 -i callme
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x004006d0 GLOBAL FUNC       puts
2   0x004006e0 GLOBAL FUNC       printf
3   0x004006f0 GLOBAL FUNC       callme_three
4   0x00400700 GLOBAL FUNC       memset
5   0x00400710 GLOBAL FUNC       read
6   0x00000000 GLOBAL FUNC       __libc_start_main
7   0x00400720 GLOBAL FUNC       callme_one
8   0x00000000 WEAK   NOTYPE     __gmon_start__
9   0x00400730 GLOBAL FUNC       setvbuf
10  0x00400740 GLOBAL FUNC       callme_two
11  0x00400750 GLOBAL FUNC       exit

yop@yop-VirtualBox:~/yolo/YoloToolbox/machines/ropemporium/03_callme$ rabin2 -R callme
[Relocations]

vaddr      paddr      type   name
―――――――――――――――――――――――――――――――――
0x00600ff0 0x00000ff0 SET_64 __libc_start_main
0x00600ff8 0x00000ff8 SET_64 __gmon_start__
0x00601018 0x00001018 SET_64 puts
0x00601020 0x00001020 SET_64 printf
0x00601028 0x00001028 SET_64 callme_three
0x00601030 0x00001030 SET_64 memset
0x00601038 0x00001038 SET_64 read
0x00601040 0x00001040 SET_64 callme_one
0x00601048 0x00001048 SET_64 setvbuf
0x00601050 0x00001050 SET_64 callme_two
0x00601058 0x00001058 SET_64 exit
0x00601070 0x00601070 ADD_64 stdout


12 relocations
```






## Cherchons les gadgets 

Pour les args 1, 2 et 3, il faut 
1: pop    rdi; ret
2: pop    rsi; ret
3: pop    rdx; ret
4: ce serait rcx
ou 1,2 et 3: pop rdi; pop rsi; pop rdx; ret

```
$ ROPgadget --binary callme | grep "pop rdi"
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
0x00000000004009a3 : pop rdi ; ret

$ ROPgadget --binary callme | grep "pop rsi"
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
0x00000000004009a1 : pop rsi ; pop r15 ; ret
0x000000000040093d : pop rsi ; pop rdx ; ret

$ ROPgadget --binary callme | grep "pop rdx"
0x000000000040093b : lcall [rdi + 0x5e] ; pop rdx ; ret
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
0x000000000040093e : pop rdx ; ret
0x000000000040093d : pop rsi ; pop rdx ; ret
```

Il y en a un qui fait la totale
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret


## Paramètres des fonctions 



## Payload 




