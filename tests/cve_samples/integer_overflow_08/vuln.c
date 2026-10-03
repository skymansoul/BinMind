/* int_overflow_08 ¡ª ÒÆÎ»Òç³ö */
#include <stdio.h>
#include <stdlib.h>
int main(){int n=1;int shifted=n<<31;char*p=malloc(shifted);free(p);return 0;}
