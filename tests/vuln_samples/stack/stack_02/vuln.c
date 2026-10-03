/* GENERIC-stack-strcpy CWE-121: strcpy向固定栈缓冲区复制超长数据 */
#include <string.h>
void cp(char*s){char b[32];strcpy(b,s);}
int main(int c,char**v){cp(c>1?v[1]:"test");return 0;}
