#include <stdio.h>
#include <string.h>
int main(int c,char **v){if(c<2)return 1;char b[256];snprintf(b,sizeof(b),v[1]);printf(b);return 0;}
