#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
char *g;void h(int s){free(g);}
int main(){g=malloc(256);signal(SIGINT,h);raise(SIGINT);puts(g);return 0;}
