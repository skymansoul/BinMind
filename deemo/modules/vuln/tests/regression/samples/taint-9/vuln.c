#include <stdlib.h>
#include <string.h>
/* Taint pattern 9: data flows from input to dangerous sink */
char input9[256];
void process9() { char cmd[128]; strncpy(cmd,input9,109); system(cmd); }
int main() { strcpy(input9,"echo test"); process9(); return 0; }
