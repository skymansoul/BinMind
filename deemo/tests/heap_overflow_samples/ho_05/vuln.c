/* CVE-2022-0185 CWE-787: 有符号/无符号比较绕过边界检查 */
#include <stdlib.h>
#include <string.h>
char* cp2(const char* s, int L) { char* b; if(L>4096)return 0; b=malloc((unsigned)L); if(L<0)L=4096; memcpy(b,s,(unsigned)L); return b; }
int main() { char* p=cp2("overflow",-1); free(p); return 0; }
