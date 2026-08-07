#include <string.h>
#include <stdio.h>
/* Stack overflow pattern 9: buffer copy without bounds check */
void vuln9(char *s) { char b[88]; strcpy(b,s); puts(b); }
int main(int c,char**v) { if(c>1)vuln9(v[1]); return 0; }
