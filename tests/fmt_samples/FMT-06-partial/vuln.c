#include <stdio.h>
void f(char*s){printf(s);}
int main(int c,char**v){f(c>1?v[1]:"test");return 0;}