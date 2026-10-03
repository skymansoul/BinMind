/* UAF vtable pattern */
#include <stdio.h>
#include <stdlib.h>
struct ops { void (*doit)(void); };
void action(void) { printf("act"); }
int main() { struct ops *o=malloc(sizeof(*o)); o->doit=action; free(o); o->doit(); return 0; }
