#include <stdio.h>
void tmpf(){char t[]="/tmp/xxxXXXXXX";FILE*f=fopen(t,"w");if(f){fputs("x",f);fclose(f);}}
int main(){tmpf();return 0;}
