/* GENERIC-realloc-leak CWE-787: realloc失败处理不当 */
#include <stdlib.h>
#include <string.h>
char* grw(char* b, size_t n) { char* nb=realloc(b,n); if(!nb)free(b); return nb?nb:b; }
int main() { char* b=grw(malloc(64),128); strcpy(b,"safe"); free(b); return 0; }
