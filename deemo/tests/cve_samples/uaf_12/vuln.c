#include <stdio.h>
#include <stdlib.h>
int main(){char*p=malloc(4096);free(p);p[0]=0;return 0;}
