#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) { if(argc<2)return 1;
char buf[64]; snprintf(buf,64,argv[1]);
write(1,buf,strlen(buf)); return 0; }
