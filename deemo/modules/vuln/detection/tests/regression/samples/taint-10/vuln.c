#include <stdlib.h>
#include <string.h>
/* Taint pattern 10: data flows from input to dangerous sink */
char input10[256];
void process10() { char cmd[128]; strncpy(cmd,input10,110); system(cmd); }
int main() { strcpy(input10,"echo test"); process10(); return 0; }
