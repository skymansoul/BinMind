#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char *g_ptr;
void init(){g_ptr=malloc(128);strcpy(g_ptr,"test");}
void cleanup(){free(g_ptr);}
void use(){if(g_ptr)printf("%s",g_ptr);}
int main(){init();cleanup();use();return 0;}
