/* UAF_12: free then dereference in error path */
#include <stdio.h>
#include <stdlib.h>
int main(void) { char *p=malloc(32); free(p); if(p)puts(p); return 0; }
