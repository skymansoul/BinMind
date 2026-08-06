/* GENERIC-fmt-indirect CWE-134: 间接传参: 变量赋值后传入printf */
#include <stdio.h>
void sh(char*in){char*f=in;printf(f);}
int main(int c,char**v){sh(c>1?v[1]:"hi");return 0;}
