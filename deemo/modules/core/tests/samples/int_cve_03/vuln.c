#include <stdlib.h>
void vuln(unsigned long long sz) { unsigned s=(unsigned)sz; malloc(s); }
int main(){vuln(0x100000010);}