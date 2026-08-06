/* GENERIC-fmt-fprintf CWE-134: fprintf格式串来自用户输入 */
#include <stdio.h>
void el(char*m){fprintf(stderr,m);}
int main(int c,char**v){el(c>1?v[1]:"ok");return 0;}
