#include <stdlib.h>
#include <string.h>
/* Taint pattern 7: data flows from input to dangerous sink */
char input7[256];
void process7() { char cmd[128]; strncpy(cmd,input7,107); system(cmd); }
int main() { strcpy(input7,"echo test"); process7(); return 0; }
