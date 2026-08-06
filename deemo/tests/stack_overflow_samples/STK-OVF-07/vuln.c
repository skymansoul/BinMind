#include <string.h>
void p(char*s){char q[32];strncpy(q,s,128);}
int main(int c,char**v){if(c>1)p(v[1]);return 0;}