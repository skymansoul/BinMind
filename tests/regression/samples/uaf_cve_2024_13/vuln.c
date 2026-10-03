/* UAF struct field */
#include <stdio.h>
#include <stdlib.h>
struct rec { int id; char name[32]; };
int main() { struct rec *r=malloc(sizeof(*r)); r->id=1; free(r); printf("%d",r->id); return 0; }
