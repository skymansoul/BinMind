#include <stdlib.h>
#include <string.h>
/* Taint pattern 12: data flows from input to dangerous sink */
char input12[256];
void process12() { char cmd[128]; strncpy(cmd,input12,112); system(cmd); }
int main() { strcpy(input12,"echo test"); process12(); return 0; }
