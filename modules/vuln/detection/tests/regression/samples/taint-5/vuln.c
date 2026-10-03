#include <stdlib.h>
#include <string.h>
/* Taint pattern 5: data flows from input to dangerous sink */
char input5[256];
void process5() { char cmd[128]; strncpy(cmd,input5,105); system(cmd); }
int main() { strcpy(input5,"echo test"); process5(); return 0; }
