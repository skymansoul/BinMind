#include <stdlib.h>
#include <stdio.h>
int*p=NULL;
void a(){p=malloc(16);*p=42;}
void b(){free(p);}
void c(){printf("%d",*p);}
int main(){a();b();c();return 0;}