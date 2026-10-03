/* GENERIC-fmt-err-verbose CWE-134: 错误日志格式串可控 */
#include <stdio.h>
void el2(int eno,char*ctx){fprintf(stderr,ctx,eno);}
int main(int c,char**v){el2(42,c>1?v[1]:"error %d");return 0;}
