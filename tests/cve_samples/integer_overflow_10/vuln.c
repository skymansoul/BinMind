/* int_overflow_10 ¡ª calloc nmemb*sizeÒç³ö */
#include <stdio.h>
#include <stdlib.h>
int main(){int*p=calloc(0x10000,0x10000);if(p)free(p);return 0;}
