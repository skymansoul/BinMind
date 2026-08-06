#include <stdio.h>
void log(char*m,char*a){fprintf(stderr,m,a);}
int main(int c,char**v){log(c>1?v[1]:"%s","test");return 0;}