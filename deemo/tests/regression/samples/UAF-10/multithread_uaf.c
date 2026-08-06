#include <stdlib.h>
/* UAF race condition pattern (simplified) */
static char *shared=NULL;
void worker() { free(shared); }
int main() { shared=malloc(1024); worker(); shared[0]='x'; return 0; }