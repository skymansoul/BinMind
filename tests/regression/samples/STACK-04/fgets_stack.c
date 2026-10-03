#include <stdio.h>
/* fgets with oversized count */
int main() { char b[16]; fgets(b,256,stdin); return 0; }