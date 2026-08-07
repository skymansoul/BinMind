#include <stdlib.h>
void vuln(int alloc, int used) { malloc(alloc-used); }
int main(){vuln(50,300);}