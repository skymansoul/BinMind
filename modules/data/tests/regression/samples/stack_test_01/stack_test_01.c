#include <string.h>
void vuln(const char *s) { char buf[32]; strcpy(buf,s); }
int main(int c,char**v) { vuln(c>1?v[1]:"A"*50); return 0; }