#include <stdio.h>
void deep(char *s,int d){if(d<=0)printf(s);else deep(s,d-1);}
int main(int c,char **v){if(c<2)return 1;deep(v[1],2);return 0;}
