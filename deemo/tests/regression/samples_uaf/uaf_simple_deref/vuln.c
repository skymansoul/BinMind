#include <stdio.h>
#include <stdlib.h>
struct obj { int id; char data[32]; };
void vuln() { struct obj *p = malloc(sizeof(struct obj)); p->id = 42;
free(p); printf("%d\n", p->id); }
int main() { vuln(); return 0; }
