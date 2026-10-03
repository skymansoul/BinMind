#include <string.h>
void vuln(const char *a,const char *b) { char buf[48]; strcpy(buf,a); strcat(buf,b); }
int main(int c,char**v) { vuln("A"*30,"B"*30); return 0; }