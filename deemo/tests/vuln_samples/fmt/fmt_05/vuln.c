/* CVE-2017-1000253 CWE-134: 内核格式串漏洞 (简化复现) */
#include <stdio.h>
#include <stdlib.h>
void kl(char*u){char*b=malloc(512);snprintf(b,512,"%s",u);printf(b);free(b);}
int main(int c,char**v){kl(c>1?v[1]:"info");return 0;}
