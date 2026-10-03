#include <stdlib.h>
#include <string.h>
/* Taint pattern 3: data flows from input to dangerous sink */
char input3[256];
void process3() { char cmd[128]; strncpy(cmd,input3,103); system(cmd); }
int main() { strcpy(input3,"echo test"); process3(); return 0; }
