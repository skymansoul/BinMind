#include <stdio.h>
#include <string.h>
int main(int c,char**v) { if(c>1){char b[256];sprintf(b,v[1]);fprintf(stdout,"%s",b);} return 0; }
