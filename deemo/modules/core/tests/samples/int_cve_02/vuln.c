#include <stdlib.h>
void vuln(unsigned o, unsigned l) { char b[256]; if(o+l<256) b[o]=0; }
int main(){vuln(0xFFFFFFF0,256);}