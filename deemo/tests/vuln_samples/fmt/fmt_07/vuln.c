/* GENERIC-fmt-snprintf-indirect CWE-134: snprintf间接格式串 */
#include <stdio.h>
char gb[256];
void isf(char*f,char*a){snprintf(gb,sizeof(gb),f,a);puts(gb);}
int main(int c,char**v){isf(c>1?v[1]:"%s",c>2?v[2]:"guest");return 0;}
