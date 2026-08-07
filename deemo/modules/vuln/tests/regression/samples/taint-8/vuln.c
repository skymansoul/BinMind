#include <stdlib.h>
#include <string.h>
/* Taint pattern 8: data flows from input to dangerous sink */
char input8[256];
void process8() { char cmd[128]; strncpy(cmd,input8,108); system(cmd); }
int main() { strcpy(input8,"echo test"); process8(); return 0; }
