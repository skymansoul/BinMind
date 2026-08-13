#include <stdio.h>
__attribute__((noinline)) void f(void){ printf("static text"); }
int main(void){ f(); return 0; }
