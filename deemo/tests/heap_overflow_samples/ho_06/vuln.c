/* CVE-2023-3269 CWE-787: realloc缩小后写超出新大小 */
#include <stdlib.h>
#include <string.h>
char* rs(char* b, size_t o, size_t n) { char* nb=realloc(b,n); if(nb&&n<o)memset(nb+n,0,o-n); return nb?nb:b; }
int main() { char* b=malloc(4096); b=rs(b,4096,2048); free(b); return 0; }
