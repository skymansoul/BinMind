/* DCG-FP-002: alloc和copy使用不同常量, 但通过add/sub链关联
 * alloc_size=128 → malloc(128)
 * copy_size = alloc_size + 16 → memcpy(dst, src, alloc_size+16)
 * 值流引擎: 追踪到128和144, 144>128+8→溢出
 * DCG: 通过add链可证copy = alloc + 16, 即copy-alloc≤16 → 若margin=16则SAFE
 */
#include <stdlib.h>
#include <string.h>

void vuln_add_chain(int pad) {
    int base_size = 128;
    int alloc_size = base_size + pad;  // pad=0时alloc=128
    int copy_size = alloc_size + 16;   // copy=144, 包含header

    char *buf = (char *)malloc(alloc_size);
    if (!buf) return;

    // 有意的headroom: copy=alloc+16, 预留header空间
    // DCG可证copy-alloc≤16 → margin=16时判为SAFE
    memcpy(buf, "data_with_16byte_header_padding", copy_size);

    free(buf);
}

int main() {
    vuln_add_chain(0);
    return 0;
}
