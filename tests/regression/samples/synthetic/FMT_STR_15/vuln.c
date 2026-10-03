/* FMT_STR_15 sample */#include <stdio.h>#include <stdlib.h>#include <string.h>int main(int c,char**v){char*b=malloc(64);memcpy(b,v[1]?:"",128);free(b);return 0;}
