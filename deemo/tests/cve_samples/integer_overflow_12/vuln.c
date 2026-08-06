/* integer_overflow_12 ¡ª uint16³Ë·¨Òç³ö */
#include <stdio.h>
#include <stdlib.h>
int main(){unsigned short n=1024;unsigned int sz=n*n;char*p=malloc(sz);free(p);return 0;}
