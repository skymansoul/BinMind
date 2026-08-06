#include <stdlib.h>
#include <string.h>
/* Taint pattern 4: data flows from input to dangerous sink */
char input4[256];
void process4() { char cmd[128]; strncpy(cmd,input4,104); system(cmd); }
int main() { strcpy(input4,"echo test"); process4(); return 0; }
