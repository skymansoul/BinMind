#include <stdlib.h>
void vuln(unsigned n, unsigned sz) { malloc(n*sz); }
int main(){vuln(65536,65536);}