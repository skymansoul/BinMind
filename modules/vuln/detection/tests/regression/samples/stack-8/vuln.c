#include <string.h>
#include <stdio.h>
/* Stack overflow pattern 8: buffer copy without bounds check */
void vuln8(char *s) { char b[80]; strcpy(b,s); puts(b); }
int main(int c,char**v) { if(c>1)vuln8(v[1]); return 0; }
