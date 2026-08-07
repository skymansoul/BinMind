"""整数溢出测试样本数据 — 16 个 C 源码整数溢出模式定义.

创建: 2026-04-16
用途: 覆盖加法/乘法/左移/符号混淆/16位截断/alloc上下文等溢出模式.
      12 TP + 4 TN.
"""

INT_SAMPLES = [
    {
        'id': 'sample01_add_overflow',
        'title': 'Basic Addition Overflow — INT_MAX + 1 wraps to negative',
        'pattern': 'if (x + 1 < x) → overflow check bypassed',
        'expected': 'TP',
        'trigger': 'INT_MAX + 1 → INT_MIN (signed wrap)',
        'code': r'''#include <stdio.h>
#include <limits.h>

int main(void) {
    int x = INT_MAX;
    int y = x + 1;  /* OVERFLOW: signed wrap to INT_MIN */
    printf("INT_MAX + 1 = %d\n", y);
    return 0;
}
''',
    },
    {
        'id': 'sample02_mul_overflow',
        'title': 'Multiplication Overflow — large * large wraps',
        'pattern': 'a * b where a*b > INT_MAX → wrap',
        'expected': 'TP',
        'trigger': '0x40000000 * 4 = 0 (32-bit wrap)',
        'code': r'''#include <stdio.h>

int main(void) {
    int a = 0x40000000;  /* 1073741824 */
    int b = 4;
    int c = a * b;  /* OVERFLOW: 0x100000000 → truncated to 0 */
    printf("0x40000000 * 4 = %d (0x%x)\n", c, c);
    return 0;
}
''',
    },
    {
        'id': 'sample03_shl_overflow',
        'title': 'Left Shift Overflow — shift past bit width',
        'pattern': 'x << N where MSB shifts out → wrap',
        'expected': 'TP',
        'trigger': '0x40000000 << 2 = 0 (32-bit shl overflow)',
        'code': r'''#include <stdio.h>

int main(void) {
    unsigned int x = 0x40000000;
    unsigned int y = x << 2;  /* OVERFLOW: bit 30→32 = 0 in 32-bit */
    printf("0x40000000 << 2 = 0x%x\n", y);
    return 0;
}
''',
    },
    {
        'id': 'sample04_alloc_size_overflow',
        'title': 'Allocation Size Overflow — malloc(nelem * size) wraps',
        'pattern': 'malloc(n * sizeof(T)) where n*size wraps → tiny alloc',
        'expected': 'TP',
        'trigger': 'malloc(0x40000001 * 4) = malloc(4)',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    /* nelem * sizeof(int) = 0x40000001 * 4 = 4 (overflow truncated) */
    size_t nelem = 0x40000001;
    size_t alloc_size = nelem * sizeof(int);
    int *buf = (int *)malloc(alloc_size);
    if (!buf) { printf("alloc failed\n"); return 1; }
    /* OVERFLOW: allocated only 4 bytes, but loop expects 0x40000001*4 */
    for (size_t i = 0; i < nelem; i++) {
        buf[i] = (int)i;  /* heap overflow at i >= 1 */
    }
    printf("overflow complete\n");
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample05_signed_unsigned_confusion',
        'title': 'Signed/Unsigned Confusion — negative int cast to size_t',
        'pattern': 'int n = -1; malloc(n) → SIZE_MAX alloc',
        'expected': 'TP',
        'trigger': 'negative int → size_t → huge alloc or wrap',
        'code': r'''#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int n = -1;
    /* n cast to size_t → SIZE_MAX (huge allocation) */
    size_t sz = (size_t)n;
    char *buf = (char *)malloc(sz);
    if (!buf) {
        printf("malloc(%zu) failed (expected)\n", sz);
        return 0;
    }
    printf("unexpected: malloc(-1) succeeded\n");
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample06_16bit_truncation',
        'title': '16-bit Truncation Overflow — 32-bit value truncated to 16-bit',
        'pattern': 'mov ax, large_imm → 16-bit truncation → overflow in alloc',
        'expected': 'TP',
        'trigger': '0x10000 → ax = 0 (16-bit zero)',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    uint32_t big = 0x10000;  /* 65536 */
    uint16_t small = (uint16_t)big;  /* truncation: 65536 → 0 */
    /* alloc(0) may succeed → use as if 65536 bytes available */
    char *buf = (char *)malloc(small ? small : 1);
    if (!buf) return 1;
    /* OVERFLOW intent: big=65536 but only 1 byte allocated */
    printf("16-bit truncated: %u → %u\n", big, small);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample07_sub_underflow',
        'title': 'Subtraction Underflow — INT_MIN - 1 wraps to INT_MAX',
        'pattern': 'x - 1 > x when x = INT_MIN → wrap',
        'expected': 'TP',
        'trigger': 'INT_MIN - 1 → INT_MAX (signed underflow)',
        'code': r'''#include <stdio.h>
#include <limits.h>

int main(void) {
    int x = INT_MIN;
    int y = x - 1;  /* UNDERFLOW: signed wrap to INT_MAX */
    printf("INT_MIN - 1 = %d\n", y);
    return 0;
}
''',
    },
    {
        'id': 'sample08_callc_overflow',
        'title': 'calloc Overflow — nmemb * size wrap in calloc',
        'pattern': 'calloc(n, size) where n*size wraps → tiny alloc',
        'expected': 'TP',
        'trigger': 'calloc(0x10000001, 4) allocates only 4 bytes',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    size_t n = 0x10000001;
    size_t sz = 4;
    /* calloc(n, sz) → n*sz wraps to 4 bytes */
    int *buf = (int *)calloc(n, sz);
    if (!buf) { printf("calloc failed\n"); return 1; }
    /* OVERFLOW: expects n*4 bytes, got only 4 */
    buf[0] = 42;
    buf[n-1] = 99;  /* writes far past allocated region */
    printf("calloc overflow: buf[%zu] = %d\n", n-1, buf[n-1]);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample09_loop_accumulate',
        'title': 'Loop Accumulation Overflow — sum grows past INT_MAX',
        'pattern': 'for(i=0;i<n;i++) sum += large_val → overflow',
        'expected': 'TP',
        'trigger': 'accumulated sum wraps in loop body',
        'code': r'''#include <stdio.h>
#include <limits.h>

int main(void) {
    int sum = INT_MAX - 10;
    int addends[] = {5, 5, 5, 5, 5};
    for (int i = 0; i < 5; i++) {
        sum += addends[i];  /* OVERFLOW: sum wraps at i=2 */
    }
    printf("accumulated sum = %d\n", sum);
    return 0;
}
''',
    },
    {
        'id': 'sample10_realloc_size_overflow',
        'title': 'realloc Size Overflow — new_size wraps',
        'pattern': 'realloc(p, n*m) where n*m wraps → shrinks buffer',
        'expected': 'TP',
        'trigger': 'realloc with overflowed size frees or shrinks',
        'code': r'''#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *p = (char *)malloc(1024);
    if (!p) return 1;
    /* n*size wraps: 0x40000001 * 4 = 4 */
    size_t n = 0x40000001;
    char *q = (char *)realloc(p, n * 4);
    if (q) {
        p = q;
        /* OVERFLOW: thinks it has 0x40000001*4 bytes, has only 4 */
        p[1000] = 'X';  /* heap overflow */
        printf("realloc overflow: p[1000] = %c\n", p[1000]);
    }
    free(p);
    return 0;
}
''',
    },
    {
        'id': 'sample11_imul_overflow',
        'title': 'imul Overflow — signed multiply with OF flag set',
        'pattern': 'imul eax, edx → OF set → result truncated',
        'expected': 'TP',
        'trigger': 'signed multiply result > 2^31-1 → OF=1',
        'code': r'''#include <stdio.h>
#include <limits.h>

int checked_multiply(int a, int b, int *result) {
    /* naive check misses edge cases */
    if (a > 0 && b > 0 && a > INT_MAX / b) {
        return 0;  /* overflow detected */
    }
    *result = a * b;  /* OVERFLOW: may still overflow for negative */
    return 1;
}

int main(void) {
    int result;
    int ok = checked_multiply(INT_MIN, -1, &result);
    printf("checked: %d, result: %d\n", ok, result);
    return 0;
}
''',
    },
    {
        'id': 'sample12_cross_func_overflow',
        'title': 'Cross-Function Overflow — overflow in callee impacts caller alloc',
        'pattern': 'callee returns overflowed size → caller uses for malloc',
        'expected': 'TP',
        'trigger': 'compute_size() overflows → caller allocs too little',
        'code': r'''#include <stdio.h>
#include <stdlib.h>

size_t compute_size(int n) {
    /* OVERFLOW: n*sizeof(int) wraps for large n */
    return (size_t)(n * (int)sizeof(int));
}

int main(void) {
    int n = 0x40000001;
    size_t sz = compute_size(n);
    int *buf = (int *)malloc(sz);
    if (!buf) { printf("alloc failed\n"); return 1; }
    /* sz=4, but n=0x40000001 → heap overflow */
    buf[n-1] = 42;
    printf("cross-func overflow: sz=%zu, buf[%d]=%d\n", sz, n-1, buf[n-1]);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample13_guard_safe',
        'title': 'Safe: Explicit Overflow Guard (no vuln)',
        'pattern': 'if (a > INT_MAX - b) return error; → safe',
        'expected': 'TN',
        'trigger': 'explicit overflow check before add',
        'code': r'''#include <stdio.h>
#include <limits.h>
#include <stdlib.h>

int main(void) {
    int a = INT_MAX;
    int b = 10;
    /* SAFE: explicit overflow guard */
    if (a > INT_MAX - b) {
        printf("overflow prevented\n");
        return 1;
    }
    int c = a + b;
    printf("safe: %d\n", c);
    return 0;
}
''',
    },
    {
        'id': 'sample14_bounds_check_safe',
        'title': 'Safe: Bounds-Checked Multiplication (no vuln)',
        'pattern': 'if (n > SIZE_MAX / sizeof(T)) return NULL; → safe',
        'expected': 'TN',
        'trigger': 'size check before malloc prevents overflow',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void *safe_alloc(size_t nmemb, size_t size) {
    if (nmemb > 0 && size > SIZE_MAX / nmemb) {
        return NULL;  /* SAFE: overflow check */
    }
    return calloc(nmemb, size);
}

int main(void) {
    size_t n = 100;
    int *buf = (int *)safe_alloc(n, sizeof(int));
    if (!buf) { printf("alloc failed\n"); return 1; }
    for (size_t i = 0; i < n; i++) buf[i] = (int)i;
    printf("safe bounds: buf[99] = %d\n", buf[99]);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample15_constant_safe',
        'title': 'Safe: Constant-Size Allocation (no vuln)',
        'pattern': 'malloc(CONST) with compile-time constant → safe',
        'expected': 'TN',
        'trigger': 'constant allocation size, no arithmetic',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 256

int main(void) {
    /* SAFE: constant size, no overflow possible */
    char *buf = (char *)malloc(BUF_SIZE);
    if (!buf) return 1;
    strncpy(buf, "constant allocation", BUF_SIZE - 1);
    buf[BUF_SIZE - 1] = '\0';
    printf("safe constant: %s\n", buf);
    free(buf);
    return 0;
}
''',
    },
    {
        'id': 'sample16_checked_arithmetic_safe',
        'title': 'Safe: Built-in Checked Arithmetic (no vuln)',
        'pattern': '__builtin_add_overflow() → compiler-provided safe add',
        'expected': 'TN',
        'trigger': 'GCC builtin overflow check catches wrap',
        'code': r'''#include <stdio.h>
#include <limits.h>

int main(void) {
    int a = INT_MAX;
    int b = 1;
    int result;
    /* SAFE: compiler builtin overflow detection */
    if (__builtin_add_overflow(a, b, &result)) {
        printf("overflow detected by builtin\n");
        return 1;
    }
    printf("result: %d\n", result);
    return 0;
}
''',
    },
]
