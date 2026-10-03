#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char *g_ptr;
void init() { g_ptr = malloc(256); memcpy(g_ptr, "data", 4); }
void cleanup() { free(g_ptr); g_ptr = NULL; /* FIX: NULL assignment removed for demo */ }
void use() { if(g_ptr) printf("data: %s", g_ptr); } /* UAF */
int main() { init(); cleanup();
    /* re-establish dangling pointer: */ g_ptr = (char*)0x41414141;
    use(); return 0; }