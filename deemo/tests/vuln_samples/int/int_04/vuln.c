/* GENERIC-int-sign-compare CWE-190: 有符号/无符号混用绕过边界检查 */
#include <stdlib.h>
void cp2(const char*s,int sz){if(sz>4096)return;char*b=malloc((unsigned)sz);free(b);}
int main(){cp2("test",-1);return 0;}
