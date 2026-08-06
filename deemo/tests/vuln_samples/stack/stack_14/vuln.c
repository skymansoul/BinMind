/* GENERIC-stack-safe-snprintf SAFE: snprintf正确使用边界检查——安全不应检出 */
#include <stdio.h>
void sf(char*n){char b[64];snprintf(b,sizeof(b),"%s",n);}
int main(int c,char**v){sf(c>1?v[1]:"guest");return 0;}
