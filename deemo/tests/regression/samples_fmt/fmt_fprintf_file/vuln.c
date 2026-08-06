#include <stdio.h>
int main(int c,char **v){if(c<2)return 1;FILE *f=fopen("/dev/null","w");
if(f){fprintf(f,v[1]);fclose(f);}return 0;}
