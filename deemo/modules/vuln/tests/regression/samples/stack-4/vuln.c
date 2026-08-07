#include <string.h>
#include <stdio.h>
/* Stack overflow pattern 4: buffer copy without bounds check */
void vuln4(char *s) { char b[48]; strcpy(b,s); puts(b); }
int main(int c,char**v) { if(c>1)vuln4(v[1]); return 0; }
