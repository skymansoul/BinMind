#include <string.h>
void f2(char*s){char buf[16];char*p=buf;while(*s)*p++=*s++;}
int main(int c,char**v){if(c>1)f2(v[1]);return 0;}