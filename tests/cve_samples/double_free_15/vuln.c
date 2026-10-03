/* double_free_15 ¡ª Ç³¿½±´µ¼ÖÂË«ÖØÊÍ·Å */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct{char*data;}Buf;
int main(){Buf a,b;a.data=malloc(128);memcpy(&b,&a,sizeof(Buf));free(a.data);free(b.data);return 0;}
