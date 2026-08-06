/* GENERIC-stack-loop-overflow CWE-121: 循环中栈缓冲区索引越界 */
#include <string.h>
void lp(char*s){char b[32];for(int i=0;i<=strlen(s);i++)b[i]=s[i];}
int main(int c,char**v){lp(c>1?v[1]:"test");return 0;}
