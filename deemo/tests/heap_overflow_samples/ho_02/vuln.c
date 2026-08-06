/* CVE-2014-0160 CWE-126: memcpy使用攻击者声明的长度而非实际大小 */
#include <stdlib.h>
#include <string.h>
typedef struct { int len; char* d; } P;
P* make(int L, const char* s, int sl) { P* p=malloc(sizeof(P)); p->len=L; p->d=malloc(L); memcpy(p->d,s,L); return p; }
int main() { P* p=make(256,"s",1); free(p->d); free(p); return 0; }
