#include <string.h>
void m(char*s){int n=strlen(s);char w[64];memcpy(w,s,n);}
int main(int c,char**v){if(c>1)m(v[1]);return 0;}