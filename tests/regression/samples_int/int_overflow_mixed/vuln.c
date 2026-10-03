#include <stdio.h>
#include <stdlib.h>
void combo(int a,short b,char c){int sz=a*b+c;char *p=malloc(sz);free(p);}
int main(){combo(32768,2,1);return 0;}
