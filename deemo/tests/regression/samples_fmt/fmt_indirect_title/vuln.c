#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) { if(argc<2)return 1;
char t[256]; snprintf(t,sizeof(t),"proc: %s",argv[1]);
printf(t); return 0; }
