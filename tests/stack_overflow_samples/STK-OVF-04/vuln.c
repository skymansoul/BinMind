#include <stdio.h>
void k(char*s){char z[256];sprintf(z,"%s",s);}
int main(int c,char**v){if(c>1)k(v[1]);return 0;}