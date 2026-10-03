#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF: ctx freed then used via cached pointer */
typedef struct{int id;char*d;}Ctx;
Ctx*g=NULL;
void create(){g=malloc(sizeof(Ctx));g->id=1;g->d=strdup("data");}
void destroy(){free(g->d);free(g);/* g not nulled */}
void use(){if(g)printf("ctx:%d",g->id);/* UAF */}
int main(){create();destroy();use();return 0;}