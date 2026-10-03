#include <stdlib.h>
#include <string.h>
int main() { char *p=malloc(64); memcpy(p,"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",128); free(p); return 0; }
