#include <string.h>
void rec(int d,char*s){char b[32];if(d>0)rec(d-1,s);strcpy(b,s);}
int main(int c,char**v){rec(c>1?atoi(v[1]):100,"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");return 0;}