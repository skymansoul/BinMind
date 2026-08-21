#include <stdio.h>
#include <stdlib.h>
void read_data(int len){if(len<0)len=-len;char *b=malloc(len);read(0,b,len);free(b);}
int main(int c,char **v){if(c>1)read_data(atoi(v[1]));return 0;}
