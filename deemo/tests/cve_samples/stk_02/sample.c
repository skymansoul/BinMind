#include <stdio.h>
#include <string.h>
void format_name(const char*n){char b[32];sprintf(b,"User: %s",n);/* BUG */printf("%s",b);}
int main(int c,char**v){if(c>1)format_name(v[1]);return 0;}