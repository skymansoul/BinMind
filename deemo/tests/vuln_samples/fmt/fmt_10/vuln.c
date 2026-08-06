/* GENERIC-fmt-snprintf-safe SAFE: snprintf正确边界检查——安全模式 */
#include <stdio.h>
char b2[256];
void sf2(char*n){snprintf(b2,sizeof(b2),"User: %s",n);puts(b2);}
int main(int c,char**v){sf2(c>1?v[1]:"anon");return 0;}
