#include <stdlib.h>
char*r=NULL;
void mk(){r=malloc(32);}
void rm(){free(r);}
void rm2(){free(r);}
int main(){mk();rm();rm2();return 0;}