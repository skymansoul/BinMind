#include <stdlib.h>
#include <string.h>
void f(char*s){int n=strlen(s);char*b=malloc(n);strcpy(b,s);free(b);}
int main(int c,char**v){if(c>1)f(v[1]);return 0;}