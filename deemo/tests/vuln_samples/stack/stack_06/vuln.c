/* GENERIC-stack-memcpy CWE-121: memcpy向栈缓冲区写入超长数据 */
#include <string.h>
void mc(const char*s,size_t l){char b[64];memcpy(b,s,l);}
int main(int c,char**v){mc(c>1?v[1]:"x",c>1?strlen(v[1])+999:5);return 0;}
