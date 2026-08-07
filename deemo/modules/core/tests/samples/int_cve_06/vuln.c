#include <stdlib.h>
void vuln(int c) { malloc(c*16); }
int main(){vuln(0x10000000);}