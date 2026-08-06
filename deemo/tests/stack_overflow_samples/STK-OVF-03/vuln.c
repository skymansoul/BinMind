#include <string.h>
void h(char*s){char y[128];strcat(y,s);}
int main(int c,char**v){if(c>1)h(v[1]);return 0;}