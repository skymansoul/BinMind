#include <stdlib.h>
#include <string.h>
/* Taint pattern 11: data flows from input to dangerous sink */
char input11[256];
void process11() { char cmd[128]; strncpy(cmd,input11,111); system(cmd); }
int main() { strcpy(input11,"echo test"); process11(); return 0; }
