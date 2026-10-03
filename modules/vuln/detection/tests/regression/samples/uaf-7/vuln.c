#include <stdlib.h>
#include <string.h>
char *g; void cleanup(){free(g);}
void use(){strcpy(g,"use");}
int main(){g=malloc(64);cleanup();use();return 0;}
