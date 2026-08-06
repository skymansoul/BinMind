#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void parse_pdf_stream(char*s,int sl){char*b=malloc(sl);memcpy(b,s,sl+8);printf("%s",b);free(b);}
int main(int c,char**v){parse_pdf_stream(v[1]?v[1]:"%PDF",c>1?strlen(v[1]):4);return 0;}