/* GENERIC-fmt-expand CWE-787: sprintf格式扩展超出malloc预算 */
#include <stdlib.h>
#include <stdio.h>
char* fmt(int n) { char* b=malloc(32); sprintf(b,"count=%d items=%d",n,n*2); return b; }
int main() { char* p=fmt(999999); free(p); return 0; }
