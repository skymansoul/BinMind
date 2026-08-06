#include <string.h>
void vuln(int n,const char *s) { char buf[32]; memcpy(buf,s,n); }
int main() { vuln(128,"A"*128); return 0; }