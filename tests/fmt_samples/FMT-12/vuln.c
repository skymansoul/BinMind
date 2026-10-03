#include <stdio.h>
int main(int c,char**v){fprintf(stdout,c>1?v[1]:"safe");return 0;}