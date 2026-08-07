#include <string.h>
#include <stdio.h>
/* Stack overflow pattern 3: buffer copy without bounds check */
void vuln3(char *s) { char b[40]; strcpy(b,s); puts(b); }
int main(int c,char**v) { if(c>1)vuln3(v[1]); return 0; }
