#include <time.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <fcntl.h>
#define USIZE 12
#define ISIZE 4

  struct f {
    char user[USIZE];
    //int user;
    int secret;
    int admin;
    int session;
  }
hey;

void flushit()
{
    char c;
    while (( c = getchar()) != '\n' && c != EOF) { }//flush input
}

void printmaps() {

    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd==0) exit(1);
    unsigned char buffer[3000];//should be enough

    memset(buffer, 0, sizeof buffer);
    read(fd, buffer, 2990);
    close(fd);
    for(int i=0;i<3000;i++)
    {
    if (buffer[i]>127){buffer[i]=0;break;}	//dont print too much
    }

    printf("\n%s\n\n", buffer);


}

void copy(unsigned char * src, unsigned char * dst,int length) {

  FILE * ptr;

  ptr = fopen(src, "rb");
  if (ptr == 0) exit(1);
  fread(dst, length, 1, ptr); /*
HTB hint: yes you can read every file you want,
but reading a sensitive file such as shadow is not the 
intended way of sovling this,...it's just an alternative way of providing input !
tmp is not listable so other players cant see your file,unless you create a guessable file such as /tmp/bof !*/

  fclose(ptr);

}



void createusername() {
    //I think  something's bad here
    unsigned char for_user[ISIZE];

    printf("\nFilename:  ");

    char fn[30];
    scanf(" %28s", & fn);

    flushit();
    copy(fn, for_user,USIZE);


    strncpy(hey.user,for_user,ISIZE+1);
    hey.user[ISIZE+1]=0;

}

char print() {

  char action = 0;

  printf("\n\n\t-----MENU-----\n1) leave message to admin\n2) print session ID\n3)login (admin only)\n4)change user\n5)exit\n\n action: ");
  fflush(stdout);
  scanf(" %1c", & action);
flushit();
  switch (action) {

  case '1':
    return '1';

  case '2':
    return '2';

  case '3':
    return '3';

  case '4':
    return '4';

  case '5':
    return '5';

  default:
    printf("\nplease type a number between 1 and 5\n");
    return 0;

  }


  fflush(stdout);
}

void printdeb(int deb) {
  printf("\ndebug info: 0x%x\n", deb);
}




void debug() {

  printf("\nthis function is problematic on purpose\n");
  printf("\nI'm trying to test some things...and that means get control of the program! \n");

  char vuln[64];

  printf("vulnerable pointer is at %x\n", vuln);
  printf("memory information on this binary:\n", vuln);

  printmaps();

  printf("\nFilename:  ");

  char fn[30];
  scanf(" %28s", & fn);
  flushit();
  copy(fn,vuln,100);//this shall trigger a buffer overflow

  return;

}

void attempt_login(int shouldbezero, int safety1, int safety2) {

  if (safety2 != safety1) {
    printf("hackeeerrrr");
    fflush(stdout);
	exit(666);
  }
  if (shouldbezero == 0) {
    printf("\naccess denied!\n");
    fflush(stdout);
  } else debug();

}

void printstr(char * s, int c) {
  printf("\nparam %s is %x\n", s, c);

}

int main(int argc, char * argv[]) {
asm(
"push $0x00000001\n"
"push $0x0003add6\n"
"push $0xb7e1a000\n"
"call 0x37efcd50\n"
"add $0x0c,%esp\n"


"push $0x00000005\n"
"push $0x0003a000\n"
"push $0xb7e1a000\n"
"call 0x37efcd50\n"
"add $0x0c,%esp\n"


);


  sleep(2);
 srand(time(0));
 int sess= rand();

  struct timeval tv;
  gettimeofday( & tv, NULL);

  int whoopsie=0;
  int protect = tv.tv_usec |0x01010101;//I hate null bytes...still secure !


  hey.secret = protect;
  hey.session = sess;
  hey.admin = 0;


  createusername();

  while (1) {
    char action = print();

    if (action == '1') {
      //I striped the code for security reasons !

    } else if (action == '2') {
      printdeb(hey.session);
    } else if (action == '3') {
      attempt_login(hey.admin, protect, hey.secret);
      //I'm changing the program ! you will never be to log in as admin...
      //I found some bugs that can do us a lot of harm...I'm trying to contain them but I think I'll have to
      //write it again from scratch !I hope it's completely harmless now ...
    }

    else if(action=='4')createusername();
    else if (action == '5') return;

  }

}
