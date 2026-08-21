#include <stdio.h>
#include <wchar.h>
int main(int c,char **v){if(c<2)return 1;wchar_t w[256];
mbstowcs(w,v[1],256);fwprintf(stderr,L"%ls",w);return 0;}
