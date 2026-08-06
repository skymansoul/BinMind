#include <stdlib.h>
#include <stdio.h>
char*q=NULL;
void x(){q=malloc(32);strcpy(q,"hi");}
void y(){q=realloc(q,64);}
void z(){printf("%s",q);free(q);}
int main(){x();y();z();return 0;}