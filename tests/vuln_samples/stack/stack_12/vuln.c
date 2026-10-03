/* GENERIC-stack-alloca CWE-121: alloca分配可变栈空间后溢出 */
#include <stdlib.h>
#include <string.h>
void al(int n){char*b=alloca(64);memset(b,0,n);}
int main(int c,char**v){al(c>1?atoi(v[1]):200);return 0;}
