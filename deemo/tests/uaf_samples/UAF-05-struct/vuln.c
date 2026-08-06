#include <stdlib.h>
typedef struct{int id;}S;
S*g=NULL;
void mk(){g=malloc(sizeof(S));g->id=1;}
void rm(){free(g);}
void use(){if(g)g->id=0;}
int main(){mk();rm();use();return 0;}