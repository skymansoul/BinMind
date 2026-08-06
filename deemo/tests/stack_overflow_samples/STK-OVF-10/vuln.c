#include <string.h>
void wrap(char*s){char x[64];strcpy(x,s);}
void mid(char*s){wrap(s);}
int main(int c,char**v){if(c>1)mid(v[1]);return 0;}