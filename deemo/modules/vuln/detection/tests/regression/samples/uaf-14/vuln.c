#include <stdlib.h>
#include <string.h>
#include <stdio.h>
void use_ptr(char *p, int f) { if(f) { free(p); puts(p); } else { strcpy(p,"safe"); free(p); } }
int main() { char *p=malloc(256); use_ptr(p,1); return 0; }
