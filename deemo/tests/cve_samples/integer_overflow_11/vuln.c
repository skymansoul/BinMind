/* int_overflow_11 ¡ª realloc sizeÒç³ö */
#include <stdio.h>
#include <stdlib.h>
int main(){char*p=malloc(64);int s=0x7FFFFFFF;int t=s+100;p=realloc(p,t);free(p);return 0;}
