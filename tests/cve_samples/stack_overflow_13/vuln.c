#include <stdio.h>
#include <stdlib.h>
int g(int x){char buf[4096];return x>0?g(x-1)+buf[0]:0;}
int main(int argc,char**argv){return g(argc>1?atoi(argv[1]):10);}
