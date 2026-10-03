#include <stdio.h>
#include <string.h>
void show_error(const char*details){char b[256];snprintf(b,256,details);/* BUG */printf("%s",b);}
int main(int c,char**v){if(c>1)show_error(v[1]);return 0;}