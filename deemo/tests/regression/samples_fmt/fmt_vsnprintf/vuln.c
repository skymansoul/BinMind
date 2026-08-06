#include <stdio.h>
#include <stdarg.h>
#include <string.h>
void logf(const char*f,...){va_list a;va_start(a,f);char b[256];
vsnprintf(b,sizeof(b),f,a);va_end(a);printf(b);}
int main(int c,char **v){if(c<2)return 1;logf(v[1]);return 0;}
