#include <stdlib.h>
char*s=NULL;
void init(){s=malloc(64);}
void fini(){free(s);free(s);}
int main(){init();fini();return 0;}