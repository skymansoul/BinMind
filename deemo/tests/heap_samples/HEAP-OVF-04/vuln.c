#include <stdlib.h>
#include <string.h>
void j(char*s){char*b=malloc(32);strcpy(b,s);free(b);}
int main(int c,char**v){j(c>1?v[1]:"A"*64);return 0;}