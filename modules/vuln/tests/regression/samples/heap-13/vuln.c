#include <stdlib.h>
#include <string.h>
int main() { char *p=malloc(32); char *q=malloc(32); memcpy(p,q,64); free(p); free(q); return 0; }
