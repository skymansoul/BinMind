/* SAFE: 栈缓冲区大小合理(1024字节) */
#include <stdio.h>
void work() {
    char buf[1024];
    buf[0] = 0;
}
int main() { work(); return 0; }
