/* GENERIC-strcat CWE-787: strcat向固定大小缓冲区追加导致溢出 */
#include <stdlib.h>
#include <string.h>
char* msg(const char* a, const char* b) { char* m=malloc(128); strcpy(m,a); strcat(m,b); return m; }
int main(int c,char**v){char*p=msg(c>1?v[1]:"hi",c>2?v[2]:"_world");free(p);return 0;}
