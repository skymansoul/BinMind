#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) { if(argc<2)return 1;
char tmp[512]; sprintf(tmp,argv[1]);
fprintf(stderr,"%s\n",tmp); return 0; }
