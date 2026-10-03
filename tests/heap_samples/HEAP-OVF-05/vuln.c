#include <stdlib.h>
#include <string.h>
void k(char*s){char*b=malloc(16);b=realloc(b,strlen(s));strcpy(b,s);free(b);}
int main(int c,char**v){k(c>1?v[1]:"test");return 0;}