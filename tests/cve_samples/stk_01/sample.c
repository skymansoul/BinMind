#include <stdio.h>
#include <string.h>
void parse_field(const char*in){char f[64];strcpy(f,in);/* BUG: no bounds */printf("%s",f);}
int main(int c,char**v){if(c>1)parse_field(v[1]);return 0;}