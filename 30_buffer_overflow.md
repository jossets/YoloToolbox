# Buffer overflow



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


## Execute stack payload : before ESP

Context:
- Executable stack
- No canary
- No Address Space Layout Randomization
=> Adresses are hard coded in elf

gcc -z execstack 




## Execute stack payload : after ESP

Context:
- Executable stack
- No canary
- No Address Space Layout Randomization
=> Adresses are hard coded in elf



## Stack/Heap non executable -> return to LibC



## Hide LibC adresse ALSR 32 bits -> bruteforce search 




## Hide LibC adresse ALSR 64 bits -> information leak (format string vuln)



## LibC hidden -> Return Oriented Program (ROP)

https://github.com/0vercl0k/rp


## Randomize location of code -> Blind ROP

[http://www.scs.stanford.edu/brop/]












