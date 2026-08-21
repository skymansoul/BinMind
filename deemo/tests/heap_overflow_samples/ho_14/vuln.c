/* GENERIC-calloc-under CWE-787: calloc参数乘积溢出 */
#include <stdlib.h>
#include <string.h>
void* mat(int r, int c) { return calloc(r,c); }
int main() { char* p=mat; if(p)strcpy(p,"t"); free(p); return 0; }
