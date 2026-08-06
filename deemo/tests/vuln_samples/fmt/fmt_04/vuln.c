/* GENERIC-fmt-syslog CWE-134: syslog格式串来自输入 */
#include <stdio.h>
void lr(char*d){printf(d);}
int main(int c,char**v){lr(c>1?v[1]:"test");return 0;}
