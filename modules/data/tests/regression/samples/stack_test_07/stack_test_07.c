#include <string.h>
void vuln(const char *s) { char buf[8]; strncpy(buf,s,strlen(s)); }
int main(int c,char**v) { vuln(c>1?v[1]:"A"*40); return 0; }