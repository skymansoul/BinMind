#include <stdlib.h>
/* UAF via global pointer */
static char *g_ptr=NULL;
void setup() { g_ptr=malloc(256); }
void teardown() { free(g_ptr); }
int main() { setup(); teardown(); g_ptr[0]='x'; return 0; }