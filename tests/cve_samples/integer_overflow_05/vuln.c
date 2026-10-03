/* int_overflow_05 ¡ª signed¼Ó·¨Òç³ö */
#include <stdio.h>
#include <stdlib.h>
int main(int argc,char**argv){int s=argc>1?atoi(argv[1]):0x7FFFFFFF;int t=s+100;char*p=malloc(t);free(p);return 0;}
