#include <stdlib.h>
#include <string.h>
/* Taint pattern 15: data flows from input to dangerous sink */
char input15[256];
void process15() { char cmd[128]; strncpy(cmd,input15,115); system(cmd); }
int main() { strcpy(input15,"echo test"); process15(); return 0; }
