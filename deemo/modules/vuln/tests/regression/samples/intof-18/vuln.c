/* intof-18: 有符号索引越界 — INT_MAX + offset → 负索引
 * mov [rbp-X], 0x7FFFFFFF; add [rbp-X], 100; movsxd rdx, eax; mov [rax+rdx], 0
 */
#include <stdlib.h>
#include <stdint.h>
int main() {
    int idx = INT32_MAX;
    idx += 100;  // signed overflow → negative
    char *p = malloc(256);
    p[idx] = 'x';  // OOB write before buffer
    free(p);
    return 0;
}
