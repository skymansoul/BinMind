#include <stdlib.h>
#include <string.h>
/* Taint pattern 2: data flows from input to dangerous sink */
char input2[256];
void process2() { char cmd[128]; strncpy(cmd,input2,102); system(cmd); }
int main() { strcpy(input2,"echo test"); process2(); return 0; }
