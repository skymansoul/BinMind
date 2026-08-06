#include <string.h>
#include <stdio.h>
/* Stack overflow pattern 7: buffer copy without bounds check */
void vuln7(char *s) { char b[72]; strcpy(b,s); puts(b); }
int main(int c,char**v) { if(c>1)vuln7(v[1]); return 0; }
