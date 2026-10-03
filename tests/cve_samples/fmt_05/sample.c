#include <stdio.h>
#include <string.h>
void smtp_helo(char*domain){printf(domain);}
int main(int c,char**v){if(c>1)smtp_helo(v[1]);return 0;}