/* CVE-2019-11477 CWE-190: size_t加法溢出导致分配不足 */
#include <stdlib.h>
#include <string.h>
void* merge(const char* a, size_t as, const char* b, size_t bs) { size_t t=as+bs; char* m=malloc(t); memcpy(m,a,as); memcpy(m+as,b,bs); return m; }
int main() { void* p=merge("a",(size_t)-10,"b",20); free(p); return 0; }
