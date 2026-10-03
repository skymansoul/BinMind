/* CVE-2024-21817 CWE-134: 格式串漏洞通过%n写入堆地址 */
#include <stdlib.h>
#include <stdio.h>
void log_u(char* in) { char* b=malloc(256); snprintf(b,256,"%s",in); printf(b); free(b); }
int main(int c,char**v){log_u(c>1?v[1]:"guest");return 0;}
