/* GENERIC-stack-sprintf CWE-121: sprintf向栈缓冲区写入超长格式化数据 */
#include <stdio.h>
void fmt(char*s){char b[32];sprintf(b,"User: %s",s);}
int main(int c,char**v){fmt(c>1?v[1]:"guest");return 0;}
