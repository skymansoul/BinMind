#include <stdio.h>
void wrap(char*f,char*a){printf(f,a);}
int main(int c,char**v){wrap(c>1?v[1]:"%d","42");return 0;}