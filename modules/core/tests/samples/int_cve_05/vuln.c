#include <stdlib.h>
void vuln(unsigned v, int s) { malloc(v<<s); }
int main(){vuln(0x10000000,8);}