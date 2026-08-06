/* UAF conditional */
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) { char *p=malloc(64); if(argc>1) free(p); puts(p); return 0; }
