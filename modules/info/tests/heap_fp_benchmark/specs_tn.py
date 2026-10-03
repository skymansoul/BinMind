TN = [
    dict(id="tn_01_equal_size_memcpy", label="tn", cwe="CWE-0",
         cve="安全模式: 分配量==写入量", title="malloc(128) + memcpy(128) 等量安全",
         trigger="直接执行 main",
         why="分配与写入严格相等, 无越界; 触发 C1 代数等价抑制",
         expect_overflow=False,
         code='''
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[128];
    memset(src, 'A', sizeof(src));
    char *buf = (char *)malloc(128);
    if (!buf) return -1;
    memcpy(buf, src, 128);
    free(buf);
    return 0;
}
'''),
    dict(id="tn_02_smaller_write", label="tn", cwe="CWE-0",
         cve="安全模式: 写入量小于分配量", title="malloc(256) + memcpy(64) 余量充足",
         trigger="直接执行 main",
         why="写入 64 远小于分配 256, C2 区间判定安全",
         expect_overflow=False,
         code='''
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[64];
    memset(src, 'B', sizeof(src));
    char *buf = (char *)malloc(256);
    if (!buf) return -1;
    memcpy(buf, src, 64);
    free(buf);
    return 0;
}
'''),
    dict(id="tn_03_early_return_guard", label="tn", cwe="CWE-0",
         cve="安全模式: 早退守卫",
         title="if(n>64) return; 支配守卫",
         trigger="任意 n",
         why="守卫保证到达 memcpy 时 n<=64, C3 支配守卫证明安全",
         expect_overflow=False,
         code='''
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    size_t n = argc > 1 ? (size_t)atoi(argv[1]) : 0;
    char src[128];
    memset(src, 'C', sizeof(src));
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    if (n > 64) return -1;
    memcpy(buf, src, n);
    free(buf);
    return 0;
}
'''),
    dict(id="tn_04_direct_block_guard", label="tn", cwe="CWE-0",
         cve="安全模式: 块内守卫",
         title="if(n<=64){memcpy} 块内守卫",
         trigger="任意 n",
         why="写入位于守卫块内, n 被钳制在 64 内",
         expect_overflow=False,
         code='''
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    size_t n = argc > 1 ? (size_t)atoi(argv[1]) : 0;
    char src[128];
    memset(src, 'D', sizeof(src));
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    if (n <= 64) { memcpy(buf, src, n); }
    free(buf);
    return 0;
}
'''),
    dict(id="tn_05_alignment_slack", label="tn", cwe="CWE-0",
         cve="安全模式: glibc 对齐松弛",
         title="malloc(28) + memcpy(28) 对齐补足",
         trigger="直接执行 main",
         why="glibc 对 malloc(28) 实际提供 32 字节可用空间, C2 对齐感知判定安全",
         expect_overflow=False,
         code='''
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[28];
    memset(src, 'E', sizeof(src));
    char *buf = (char *)malloc(28);
    if (!buf) return -1;
    memcpy(buf, src, 28);
    free(buf);
    return 0;
}
'''),
    dict(id="tn_06_calloc_correct", label="tn", cwe="CWE-0",
         cve="安全模式: calloc 正确乘法",
         title="calloc(16, sizeof(int)) + 写入 64",
         trigger="直接执行 main",
         why="calloc 分配 64 字节, 写入恰好 64, 等量安全",
         expect_overflow=False,
         code='''
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[64];
    memset(src, 'F', sizeof(src));
    int *buf = (int *)calloc(16, sizeof(int));
    if (!buf) return -1;
    memcpy(buf, src, 64);
    free(buf);
    return 0;
}
'''),
    dict(id="tn_07_strncpy_bounded", label="tn", cwe="CWE-0",
         cve="安全模式: strncpy 限定长度",
         title="malloc(128) + strncpy(buf,src,127)",
         trigger="直接执行 main",
         why="strncpy 写入上限 127 < 128, C2 判定安全",
         expect_overflow=False,
         code='''
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[256];
    memset(src, 'G', sizeof(src));
    char *buf = (char *)malloc(128);
    if (!buf) return -1;
    strncpy(buf, src, 127);
    free(buf);
    return 0;
}
'''),
    dict(id="tn_08_sizeof_match", label="tn", cwe="CWE-0",
         cve="安全模式: sizeof 尺寸匹配",
         title="malloc(n*sizeof(int)) + memcpy(n*sizeof(int))",
         trigger="任意 n",
         why="分配与写入均为 n*4, C1 代数等价抑制",
         expect_overflow=False,
         code='''
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    size_t n = argc > 1 ? (size_t)atoi(argv[1]) : 16;
    char src[1024];
    memset(src, 'H', sizeof(src));
    int *buf = (int *)malloc(n * sizeof(int));
    if (!buf) return -1;
    memcpy(buf, src, n * sizeof(int));
    free(buf);
    return 0;
}
'''),
    dict(id="tn_09_algebraic_equal", label="tn", cwe="CWE-0",
         cve="安全模式: 代数等价 (交换律)",
         title="malloc(4*n) + memcpy(n*4)",
         trigger="任意 n",
         why="4*n 与 n*4 代数等价, C1 规范化后判定安全",
         expect_overflow=False,
         code='''
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    size_t n = argc > 1 ? (size_t)atoi(argv[1]) : 16;
    char src[1024];
    memset(src, 'I', sizeof(src));
    char *buf = (char *)malloc(4 * n);
    if (!buf) return -1;
    memcpy(buf, src, n * 4);
    free(buf);
    return 0;
}
'''),
    dict(id="tn_10_unrelated_alloc", label="tn", cwe="CWE-0",
         cve="安全模式: 无关分配不关联",
         title="无关小分配 + 正确的等量写入",
         trigger="直接执行 main",
         why="malloc(32) 与写入目标 buf 无别名关系, C0 值流绑定排除跨缓冲误报",
         expect_overflow=False,
         code='''
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[128];
    memset(src, 'J', sizeof(src));
    char *other = (char *)malloc(32);
    char *buf = (char *)malloc(128);
    if (!buf) return -1;
    (void)other;
    memcpy(buf, src, 128);
    free(other);
    free(buf);
    return 0;
}
'''),
    dict(id="tn_11_snprintf_bounded", label="tn", cwe="CWE-0",
         cve="安全模式: snprintf 长度受限",
         title="malloc(128) + snprintf(buf,128)",
         trigger="直接执行 main",
         why="snprintf 显式限制 128, 不会越界 (此样本为安全对照)",
         expect_overflow=False,
         code='''
#include <stdlib.h>
#include <stdio.h>
int main(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return -1;
    snprintf(buf, 128, "%s-%d", "PREFIX", 42);
    free(buf);
    return 0;
}
'''),
    dict(id="tn_12_min_cap_guard", label="tn", cwe="CWE-0",
         cve="安全模式: min() 上界钳制",
         title="memcpy(buf,src,min(n,64)) 钳制",
         trigger="任意 n",
         why="min(n,64) 保证写入不超过 64, 与分配 64 对齐后安全",
         expect_overflow=False,
         code='''
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static size_t _min(size_t a, size_t b) { return a < b ? a : b; }
int main(int argc, char **argv) {
    size_t n = argc > 1 ? (size_t)atoi(argv[1]) : 0;
    char src[1024];
    memset(src, 'K', sizeof(src));
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    memcpy(buf, src, _min(n, 64));
    free(buf);
    return 0;
}
'''),
    dict(id="tn_13_ternary_clamp", label="tn", cwe="CWE-0",
         cve="安全模式: 三目钳制",
         title="n=(n>64)?64:n 三目钳制",
         trigger="任意 n",
         why="三目表达式将 n 钳制在 64 内, C3 钳制守卫证明安全",
         expect_overflow=False,
         code='''
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    size_t n = argc > 1 ? (size_t)atoi(argv[1]) : 0;
    char src[128];
    memset(src, 'L', sizeof(src));
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    n = (n > 64) ? 64 : n;
    memcpy(buf, src, n);
    free(buf);
    return 0;
}
'''),
    dict(id="tn_14_inbounds_offset", label="tn", cwe="CWE-0",
         cve="安全模式: 界内偏移写",
         title="malloc(64) + buf[32] 界内写",
         trigger="直接执行 main",
         why="偏移 32 小于分配 64, 无越界",
         expect_overflow=False,
         code='''
#include <stdlib.h>
int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    buf[32] = 'M';
    free(buf);
    return 0;
}
'''),
    dict(id="tn_15_realloc_grow", label="tn", cwe="CWE-0",
         cve="安全模式: realloc 扩容安全",
         title="realloc 扩容到 256 后写入 256",
         trigger="直接执行 main",
         why="realloc 扩容后分配 256, 写入恰好 256; 旧分配点被 C0 去重丢弃",
         expect_overflow=False,
         code='''
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[256];
    memset(src, 'N', sizeof(src));
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    buf = (char *)realloc(buf, 256);
    if (!buf) return -1;
    memcpy(buf, src, 256);
    free(buf);
    return 0;
}
'''),
]
