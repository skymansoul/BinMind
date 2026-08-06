#include <stdlib.h>
char*p=NULL;
void a(){p=malloc(32);}
void b(){p=realloc(p,64);}
void c(){free(p);p[0]=0;}
int main(){a();b();c();return 0;}