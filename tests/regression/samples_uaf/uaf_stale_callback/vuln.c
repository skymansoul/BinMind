#include <stdio.h>
#include <stdlib.h>
typedef void (*cb_t)(void);
struct widget { cb_t on_destroy; int data; };
void handler() { printf("freed!\n"); }
int main() { struct widget *w = malloc(sizeof(*w)); w->on_destroy = handler;
free(w); w->on_destroy(); return 0; }
