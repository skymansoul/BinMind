/* UAF-006: Cross-function UAF via global pointer */
#include <stdlib.h>
#include <stdio.h>
static char *g_ptr = NULL;
void alloc_buf(void) { g_ptr = malloc(128); }
void free_buf(void) { free(g_ptr); }
void use_buf(void) { printf("%s", g_ptr); } /* UAF if called after free_buf */
int main(void) { alloc_buf(); free_buf(); use_buf(); return 0; }
