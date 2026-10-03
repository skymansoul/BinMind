/* GENERIC-stack-nested CWE-121: 嵌套函数调用中栈缓冲区溢出 */
#include <string.h>
void inner(char*s){char b[32];strcpy(b,s);}
void outer(char*s){inner(s);}
int main(int c,char**v){outer(c>1?v[1]:"test");return 0;}
