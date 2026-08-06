/* int_overflow_04 ¡ª size_t»ØÈÆ */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(){size_t n=65535;n=n*65535;char*p=malloc(n);memcpy(p,"AAA",64);free(p);return 0;}
