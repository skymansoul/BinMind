/* DCG-FP-003: cmp约束——if(copy_size > 192) return→DCG可推断copy≤192
 * alloc_size=192, copy_size在cmp后有上界192
 * 值流引擎可能追踪不到cmp约束, 只看copy_size变量→TOP
 * DCG从cmp $192+ja收集copy_size≤192的约束→与alloc比较→SAFE
 */
#include <stdlib.h>
#include <string.h>

void vuln_cmp_bound(int user_len) {
    int alloc_size = 192;
    int copy_size = user_len;

    // 边界检查: 若copy超过alloc则直接返回
    if (copy_size > alloc_size)
        return;

    char *buf = (char *)malloc(alloc_size);
    if (!buf) return;

    // 此时copy_size保证≤alloc_size, 安全
    // DCG从cmp $192, %reg + ja的fall-through路径收集reg≤192
    memcpy(buf, "safe_data", copy_size);

    free(buf);
}

int main() {
    vuln_cmp_bound(128);
    return 0;
}
