/* int_overflow_07 ¡ª ½Ø¶Ïµ¼ÖÂ·ÖÅä²»×ã */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(){unsigned long long big=0x100000001ULL;unsigned int small=(unsigned int)big;char*p=malloc(small);memset(p,0,big);free(p);return 0;}
