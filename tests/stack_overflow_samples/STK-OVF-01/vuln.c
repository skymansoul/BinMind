#include <string.h>
void f(char*s){char b[64];strcpy(b,s);}
int main(int c,char**v){if(c>1)f(v[1]);return 0;}