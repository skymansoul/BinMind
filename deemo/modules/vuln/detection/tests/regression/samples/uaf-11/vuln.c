#include <stdlib.h>
#include <string.h>
void process(char *p) { free(p); strcpy(p,"bad"); }
int main() { char *p=malloc(128); process(p); return 0; }
