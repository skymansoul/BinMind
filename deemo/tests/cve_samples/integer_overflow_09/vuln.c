/* int_overflow_09 ¡ª ¼õ·¨ÏÂÒç */
#include <stdio.h>
#include <stdlib.h>
int main(){unsigned int a=5,b=10;unsigned int diff=a-b;char*p=malloc(diff);free(p);return 0;}
