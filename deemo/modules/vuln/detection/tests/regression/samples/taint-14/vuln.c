#include <stdlib.h>
#include <string.h>
/* Taint pattern 14: data flows from input to dangerous sink */
char input14[256];
void process14() { char cmd[128]; strncpy(cmd,input14,114); system(cmd); }
int main() { strcpy(input14,"echo test"); process14(); return 0; }
