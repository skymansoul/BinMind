/* UAF callback after free */
#include <stdio.h>
#include <stdlib.h>
typedef void (*cb_t)(void);
struct widget { int id; cb_t on_event; };
void handler(void) { printf("ok"); }
int main() { struct widget *w = malloc(sizeof(*w)); w->on_event = handler; free(w); w->on_event(); return 0; }
