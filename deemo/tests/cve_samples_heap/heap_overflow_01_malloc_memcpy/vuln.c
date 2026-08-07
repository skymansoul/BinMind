/* 基础堆溢出: malloc(固定) + memcpy(更大)
 * 预期: 堆检测器→DEFINITE OVERFLOW
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *p = (char*)malloc(64);
    memcpy(p, "AAAA...(>64 bytes)", 256);
    free(p);
    return 0;
}
