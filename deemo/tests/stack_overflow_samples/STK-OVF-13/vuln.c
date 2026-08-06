#include <stdio.h>
int main(int c,char**v){char b[64];sprintf(b,"User input: %s",c>1?v[1]:"");return 0;}