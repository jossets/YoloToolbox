# Buffer overflow



## Simple buffer overflow : overwrite a stack variable




## Execute stack payload : before ESP

Context:
- Executable stack
- No canary
- No Address Space Layout Randomization
=> Adresses are hard coded in elf









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












