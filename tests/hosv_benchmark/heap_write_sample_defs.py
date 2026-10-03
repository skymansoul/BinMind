"""
样本定义: 18 个堆溢出测试样本的源码, 期望判定, 说明文本.
源码与模板/truth/判定标签集中于此, 供 _gen_samples.py 生成样本目录.
"""

SAMPLES_DEF = [
# VULN
    ("v01_walk_escape", "CVE-2021-3156", "walk_write", "VULN",
     r'''/* CVE-2021-3156 (sudo) - malloc(strlen) 无 +1, *p++ 双步游走 */
#include <stdlib.h>
#include <string.h>
char* escape(const char* s) {
    size_t l = strlen(s);
    char* b = malloc(l + 1);
    char* p = b;
    for (const char* q = s; *q; q++) {
        if (*q == '\\') { *p++ = '\\'; }
        *p++ = *q;
    }
    *p = 0;
    return b;
}
int main(int c, char** v) {
    char* p = escape(c > 1 ? v[1] : "\\t");
    free(p);
    return 0;
}
'''),
    ("v02_walk_safe", "SAFE-ctr", "walk_write", "SAFE",
     r'''/* SAFE - 指针游走有界: malloc(strlen*2+1) 预留扩展空间 */
#include <stdlib.h>
#include <string.h>
char* escape_ok(const char* s) {
    size_t l = strlen(s);
    char* b = malloc(l * 2 + 2);
    char* p = b;
    for (const char* q = s; *q; q++) {
        if (*q == '\\') { *p++ = '\\'; }
        *p++ = *q;
    }
    *p = 0;
    return b;
}
int main(int c, char** v) {
    char* p = escape_ok(c > 1 ? v[1] : "\\t");
    free(p);
    return 0;
}
'''),
    ("v03_struct_ob1", "GENERIC-ob1", "struct_idx", "VULN",
     r'''/* off-by-one 结构体数组: for(i=0;i<=n;i++) 越界 1 元素 */
#include <stdlib.h>
typedef struct { int h; char d[64]; } Item;
void fill(Item* arr, int n) {
    for (int i = 0; i <= n; i++) arr[i].h = i;
}
int main() {
    Item* arr = malloc(10 * sizeof(Item));
    fill(arr, 10);
    free(arr);
    return 0;
}
'''),
    ("v04_struct_safe", "SAFE-str", "struct_idx", "SAFE",
     r'''/* SAFE - for(i=0;i<n;i++) 正确边界 */
#include <stdlib.h>
typedef struct { int h; char d[64]; } Item;
void fill_ok(Item* arr, int n) {
    for (int i = 0; i < n; i++) arr[i].h = i;
}
int main() {
    Item* arr = malloc(10 * sizeof(Item));
    fill_ok(arr, 10);
    free(arr);
    return 0;
}
'''),
    ("v05_scanf_oob", "CVE-2019-7304", "unbounded_io", "VULN",
     r'''/* 无界 scanf %s 到堆缓冲 */
#include <stdlib.h>
#include <stdio.h>
int main() {
    char* b = malloc(32);
    scanf("%s", b);
    free(b);
    return 0;
}
'''),
    ("v06_scanf_bounded", "SAFE-scf", "unbounded_io", "SAFE",
     r'''/* SAFE - scanf %31s 有界输入 */
#include <stdlib.h>
#include <stdio.h>
int main() {
    char* b = malloc(32);
    scanf("%31s", b);
    free(b);
    return 0;
}
'''),
    ("v07_gets_oob", "GENERIC-gets", "unbounded_io", "VULN",
     r'''/* gets 无界读入堆缓冲 */
#include <stdlib.h>
#include <stdio.h>
int main() {
    char* b = malloc(48);
    gets(b);
    free(b);
    return 0;
}
'''),
    ("v08_nullterm", "CVE-2017-1000405", "null_terminator", "VULN",
     r'''/* malloc(strlen) 缺 +1, d[l]=0 越界 */
#include <stdlib.h>
#include <string.h>
char* dup(const char* s) {
    size_t l = strlen(s);
    char* d = malloc(l);
    memcpy(d, s, l);
    d[l] = 0;
    return d;
}
int main(int c, char** v) {
    char* p = dup(c > 1 ? v[1] : "t");
    free(p);
    return 0;
}
'''),
    ("v09_nullterm_safe", "SAFE-nt", "null_terminator", "SAFE",
     r'''/* SAFE - malloc(strlen+1) 预留终止符 */
#include <stdlib.h>
#include <string.h>
char* dup_ok(const char* s) {
    size_t l = strlen(s);
    char* d = malloc(l + 1);
    memcpy(d, s, l);
    d[l] = 0;
    return d;
}
int main(int c, char** v) {
    char* p = dup_ok(c > 1 ? v[1] : "t");
    free(p);
    return 0;
}
'''),
    ("v10_calloc_wrap", "CVE-2016-10165", "factory_bind", "VULN",
     r'''/* calloc 整数回绕: 65536*65536 溢出 */
#include <stdlib.h>
#include <string.h>
void* mat(int r, int c) {
    return calloc(r, c);
}
int main() {
    char* p = (char*)mat;
    if (p) { strcpy(p, "t"); }
    free(p);
    return 0;
}
'''),
    ("v11_factory_cross", "GENERIC-fac", "factory_bind", "VULN",
     r'''/* 工厂函数返回小缓冲 + 跨函数 strcpy 溢出 */
#include <stdlib.h>
#include <string.h>
void* make_buf(int n) {
    return malloc(n);
}
int main(int c, char** v) {
    char* p = (char*)make_buf(16);
    strcpy(p, c > 1 ? v[1] : "overflow-data-payload");
    free(p);
    return 0;
}
'''),
    ("v12_factory_safe", "SAFE-fac", "factory_bind", "SAFE",
     r'''/* SAFE - 工厂返回足够缓冲 + 有界拷贝 */
#include <stdlib.h>
#include <string.h>
void* make_buf(int n) {
    return malloc(n);
}
int main(int c, char** v) {
    char* p = (char*)make_buf(128);
    strncpy(p, c > 1 ? v[1] : "hi", 63);
    p[63] = 0;
    free(p);
    return 0;
}
'''),
    ("v13_loop_memcpy", "CVE-2019-13143", "walk_write", "VULN",
     r'''/* 循环内 memcpy 到推进指针: buf+n 累积越界 */
#include <stdlib.h>
#include <string.h>
int main() {
    char* b = malloc(64);
    char* p = b;
    for (int i = 0; i < 8; i++) {
        memcpy(p, "XXXX", 16);
        p += 16;
    }
    free(b);
    return 0;
}
'''),
    ("v14_loop_safe", "SAFE-lop", "walk_write", "SAFE",
     r'''/* SAFE - 循环写量精确等于分配大小 */
#include <stdlib.h>
#include <string.h>
int main() {
    char* b = malloc(64);
    char* p = b;
    for (int i = 0; i < 4; i++) {
        memcpy(p, "XXXXXXXX", 16);
        p += 16;
    }
    free(b);
    return 0;
}
'''),
    ("v15_ptr_arith", "CVE-2021-3609", "struct_idx", "VULN",
     r'''/* 指针算术越界: p = arr; p[15] 访问超分配 */
#include <stdlib.h>
typedef struct { int h; } Hdr;
int main() {
    Hdr* arr = malloc(8 * sizeof(Hdr));
    Hdr* p = arr + 3;
    p[5].h = 42;   /* arr[8] 越界 */
    free(arr);
    return 0;
}
'''),
    ("v16_nullterm_fgets", "GENERIC-nt2", "null_terminator", "VULN",
     r'''/* fgets 后手工终止越界: buf[len-1] 已满仍写 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
int main() {
    char* b = malloc(16);
    if (fgets(b, 16, stdin)) {
        int l = (int)strlen(b);
        if (l > 0) { b[l - 1] = 0; }
    }
    free(b);
    return 0;
}
'''),
    ("v17_memcpy_oob", "CVE-2014-0160", "walk_write", "VULN",
     r'''/* memcpy 长度由外部提供且超分配 */
#include <stdlib.h>
#include <string.h>
int main(int c, char** v) {
    char* b = malloc(8);
    size_t n = c > 1 ? (size_t)atoi(v[1]) : 32;
    memcpy(b, "payload-beyond-eight-bytes", n);
    free(b);
    return 0;
}
'''),
    ("v18_guard_miss", "GENERIC-grd", "struct_idx", "VULN",
     r'''/* 守卫上限超过分配容量: if(n<=100) 但 malloc(50*sizeof) */
#include <stdlib.h>
#include <stdio.h>
typedef struct { int v; } Elem;
int main() {
    int n = 0;
    scanf("%d", &n);
    if (n <= 100) {
        Elem* a = malloc(50 * sizeof(Elem));
        for (int i = 0; i < n; i++) a[i].v = i;
        free(a);
    }
    return 0;
}
'''),
    ("v19_memcpy_equal", "SAFE-mceq", "memcpy_corr", "SAFE",
     r'''/* malloc(n) + memcpy(buf, src, n) 共享系数相等 → 安全 */
#include <stdlib.h>
#include <string.h>
int main(int c, char** v) {
    size_t n = c > 1 ? strlen(v[1]) : 4;
    char* buf = malloc(n + 1);
    memcpy(buf, "abc", n);
    buf[n] = 0;
    free(buf);
    return 0;
}
'''),
    ("v20_memcpy_double", "GENERIC-mcd", "memcpy_corr", "VULN",
     r'''/* malloc(n) + memcpy(buf, src, n*2) 写入系数大于分配 → 溢出 */
#include <stdlib.h>
#include <string.h>
int main(int c, char** v) {
    size_t n = c > 1 ? strlen(v[1]) : 4;
    char* buf = malloc(n);
    memcpy(buf, "abcdefgh", n * 2);
    free(buf);
    return 0;
}
'''),
]


README_TMPL = """# {cve} — {mode}

# CVE
{cve}

# 判定
{label}

# 为什么有效
{why}
"""

TRUTHS = {
    "v01_walk_escape": "malloc(l+1) 但游走写每字符最多 2 步 (反斜杠转义), 最长输出 2l+1 > l+1 → 溢出",
    "v02_walk_safe": "malloc(2l+2) 覆盖最长输出 2l+1 → 安全",
    "v03_struct_ob1": "i<=n 写入 n+1 个元素, 分配 n 个 → 结构越界",
    "v04_struct_safe": "i<n 写入 n 个元素 = 分配数 → 安全",
    "v05_scanf_oob": "%s 无宽度, 输入可超 32 字节",
    "v06_scanf_bounded": "%31s 限制输入 ≤31 字节 < 32 分配",
    "v07_gets_oob": "gets 无边界, 输入可超 48 字节",
    "v08_nullterm": "malloc(l) 缺终止符空间, d[l]=0 越界 1 字节",
    "v09_nullterm_safe": "malloc(l+1) 预留终止符 → 安全",
    "v10_calloc_wrap": "65536*65536 溢出 32-bit size_t → 返回 0 或过小对象",
    "v11_factory_cross": "make_buf(16) 返回 16 字节, strcpy 拷贝 >16 → 跨函数溢出",
    "v12_factory_safe": "make_buf(128) + strncpy 63 字节 → 安全",
    "v13_loop_memcpy": "8 次 × 16 字节 = 128 > 64 分配 → 循环累积越界",
    "v14_loop_safe": "4 次 × 16 字节 = 64 = 分配 → 安全",
    "v15_ptr_arith": "p=arr+3, p[5]=arr[8], 分配 8 元素 → 越界",
    "v16_nullterm_fgets": "fgets 读满 buf[15]=0 时 l-1=15 写越界 (边界情形)",
    "v17_memcpy_oob": "外部 n 可达 32, 分配仅 8 → memcpy 越界",
    "v18_guard_miss": "守卫 n<=100 仅钳制上限, 分配仅 50 个元素; n 取 51..100 时循环写越界",
    "v19_memcpy_equal": "malloc(n+1) + memcpy(n) 共享系数相等 → 安全",
    "v20_memcpy_double": "malloc(n) + memcpy(n*2) 写入系数大于分配 → 溢出",
}

LABEL_TO_VERDICT = {"VULN": "VULN", "SAFE": "SAFE"}
