/* stack_overflow_06 — scanf无宽度限定 */
#include <stdio.h>
int main() { char buf[64]; scanf("%s", buf); return 0; }
