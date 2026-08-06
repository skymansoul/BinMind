#include <stdlib.h>
#include <string.h>
/* Taint pattern 6: data flows from input to dangerous sink */
char input6[256];
void process6() { char cmd[128]; strncpy(cmd,input6,106); system(cmd); }
int main() { strcpy(input6,"echo test"); process6(); return 0; }
