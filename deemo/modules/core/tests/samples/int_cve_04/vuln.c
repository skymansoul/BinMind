#include <stdlib.h>
void vuln(int len) { unsigned n=len-1; malloc(n); }
int main(){vuln(0);}