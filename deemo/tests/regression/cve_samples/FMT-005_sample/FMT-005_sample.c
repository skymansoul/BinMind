/* FMT-005: SAFE — format is compile-time constant */
#include <stdio.h>
void show_help(void) { printf("Usage: program <input>\n"); }
int main(void) { show_help(); return 0; }
