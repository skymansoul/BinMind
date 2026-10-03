#include <stdlib.h>
void vuln(unsigned long l) { unsigned short s=(unsigned short)l; malloc(s); }
int main(){vuln(65537);}