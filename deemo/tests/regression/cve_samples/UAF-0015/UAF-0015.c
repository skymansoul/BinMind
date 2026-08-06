/* UAF-0015: Cross-function UAF via callback */
#include <stdlib.h>
#include <stdio.h>
typedef void (*cb_t)(char*);
static cb_t g_cb = NULL;
void set_cb(cb_t f) { g_cb = f; }
void do_work(char *p) { free(p); if (g_cb) g_cb(p); /* BUG: p freed, then used in callback */ }
void my_cb(char *s) { printf("%s", s); }
int main(void) { set_cb(my_cb); do_work(malloc(64)); return 0; }
