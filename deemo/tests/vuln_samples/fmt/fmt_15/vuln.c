#include <stdio.h>
void show_name(char* n) { printf("Hello, %s\n", n); }
int main(int c, char** v) { show_name(c>1?v[1]:"guest"); return 0; }
