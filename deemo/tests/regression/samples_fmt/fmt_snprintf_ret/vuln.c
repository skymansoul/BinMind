#include <stdio.h>
#include <string.h>
int main(int c,char **v){if(c<2)return 1;char b[64];int n=snprintf(b,64,v[1]);
printf(b);return 0;}
