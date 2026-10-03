/* stack_overflow_05 ¡ª read()ÎÞ±ß½ç¼ì²é */
#include <stdio.h>
#include <unistd.h>
int main() { char buf[32]; read(0, buf, 256); return 0; }
