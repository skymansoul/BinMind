/* FMT-008: SAFE variant — puts/printf literal */
#include <stdio.h>
void output(void) { puts("static message"); }
int main(void) { output(); return 0; }
