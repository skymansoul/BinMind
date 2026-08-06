/* CVE-2022-0185 CWE-416: 内核UAF: free后通过全局变量别名使用 */
#include <stdlib.h>
char*g;
void fb(char*p){free(p);g=p;}
void ub(){if(g)g[0]='X';}
int main(){char*b=malloc(128);fb(b);ub();return 0;}
