#include <stdlib.h>
#include <string.h>
/* Taint pattern 13: data flows from input to dangerous sink */
char input13[256];
void process13() { char cmd[128]; strncpy(cmd,input13,113); system(cmd); }
int main() { strcpy(input13,"echo test"); process13(); return 0; }
