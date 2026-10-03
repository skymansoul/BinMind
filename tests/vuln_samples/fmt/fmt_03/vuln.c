/* GENERIC-fmt-sprintf CWE-134: sprintf¸ñÊ½´®¿É¿Ø */
#include <stdio.h>
char b[256];
void fm(char*f,char*a){sprintf(b,f,a);puts(b);}
int main(int c,char**v){fm(c>1?v[1]:"%s",c>2?v[2]:"w");return 0;}
