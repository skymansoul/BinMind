/* VULN: 单个栈缓冲区 65536 字节 */
#include <stdio.h>
int main() {
    char buf[65536];
    buf[0] = 0;
    return 0;
}
