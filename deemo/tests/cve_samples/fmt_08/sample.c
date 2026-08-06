#include <stdio.h>
#include <string.h>
void vpn_log(char*ev){fprintf(stderr,ev);}
int main(int c,char**v){if(c>1)vpn_log(v[1]);return 0;}