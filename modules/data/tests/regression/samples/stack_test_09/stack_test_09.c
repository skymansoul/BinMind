#include <string.h>
void vuln(const char *s) { char buf[40]; memmove(buf,s,strlen(s)+1); }
int main(int c,char**v) { vuln(c>1?v[1]:"A"*50); return 0; }