#include <string.h>
#include <stdio.h>
/* Stack overflow pattern 13: buffer copy without bounds check */
void vuln13(char *s) { char b[120]; strcpy(b,s); puts(b); }
int main(int c,char**v) { if(c>1)vuln13(v[1]); return 0; }
