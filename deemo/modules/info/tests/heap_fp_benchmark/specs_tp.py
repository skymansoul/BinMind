TP = [
    dict(id="tp_01_memcpy_const_mismatch", label="tp", cwe="CWE-122",
         cve="CVE-2024-001 类比 (malloc/memcpy 常量尺寸错配)",
         title="malloc(32) + memcpy(64) 常量错配堆溢出",
         trigger="直接执行 main",
         why="分配 32 字节而写入 64 字节, 溢出量为确定常量, 静态可证",
         expect_overflow=True,
         code='''
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[64];
    memset(src, 'A', sizeof(src));
    char *buf = (char *)malloc(32);
    if (!buf) return -1;
    memcpy(buf, src, 64);
    free(buf);
    return 0;
}
'''),
    dict(id="tp_02_tainted_size_write", label="tp", cwe="CWE-122",
         cve="CVE-2021-3156 类 (sudo_heap) 输入尺寸驱动溢出",
         title="argv 驱动的写入尺寸超过固定分配",
         trigger="./sample 4096 (n>64 即溢出)",
         why="写入量 n 来自攻击者输入而分配量为固定 64, 无任何边界守卫",
         expect_overflow=True,
         code='''
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    size_t n = 0;
    if (argc > 1) n = (size_t)atoi(argv[1]);
    char src[256];
    memset(src, 'A', sizeof(src));
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    memcpy(buf, src, n);
    free(buf);
    return 0;
}
'''),
    dict(id="tp_03_off_by_one_memcpy", label="tp", cwe="CWE-193",
         cve="CVE-2017-1000371 类 (off-by-one 堆溢出)",
         title="memcpy 越界 1 字节 (off-by-one)",
         trigger="直接执行 main",
         why="malloc(64) 对齐后可用 64 字节, 写入 65 字节必然越界",
         expect_overflow=True,
         code='''
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[65];
    memset(src, 'B', sizeof(src));
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    memcpy(buf, src, 65);
    free(buf);
    return 0;
}
'''),
    dict(id="tp_04_strcpy_unbounded", label="tp", cwe="CWE-122",
         cve="CVE-2015-0235 (GHOST) 类 无界字符串拷贝到堆",
         title="strcpy 无界写入堆缓冲区",
         trigger="直接执行 main",
         why="strcpy 以 NUL 终止为界, 源长于目标缓冲区即溢出, 写入量无上界",
         expect_overflow=True,
         code='''
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[128];
    memset(src, 'C', sizeof(src) - 1);
    src[sizeof(src) - 1] = '\\0';
    char *buf = (char *)malloc(32);
    if (!buf) return -1;
    strcpy(buf, src);
    free(buf);
    return 0;
}
'''),
    dict(id="tp_05_loop_write_overflow", label="tp", cwe="CWE-122",
         cve="CVE-2022-22623 类 (循环逐字节堆写)",
         title="循环逐字节写入越过分配边界",
         trigger="直接执行 main",
         why="while 循环以固定次数 (64) 逐字节写入 16 字节缓冲区",
         expect_overflow=True,
         code='''
#include <stdlib.h>
int main(void) {
    char *buf = (char *)malloc(16);
    if (!buf) return -1;
    int i = 0;
    while (i < 64) { buf[i++] = 'D'; }
    free(buf);
    return 0;
}
'''),
    dict(id="tp_06_int_overflow_malloc", label="tp", cwe="CWE-190",
         cve="CVE-2016-7117 / CVE-2017-1000112 类 (整型溢出致小分配大写入)",
         title="整型溢出导致小 chunk + 大写入",
         trigger="./sample 0x40000000 (count*4 回绕)",
         why="count*4 发生无符号回绕得到小分配, 随后 4096 字节写入必然越界",
         expect_overflow=True,
         code='''
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    unsigned count = argc > 1 ? (unsigned)atoi(argv[1]) : 0;
    char src[4096];
    memset(src, 'E', sizeof(src));
    char *buf = (char *)malloc(count * 4);
    if (!buf) return -1;
    memcpy(buf, src, sizeof(src));
    free(buf);
    return 0;
}
'''),
    dict(id="tp_07_realloc_shrink", label="tp", cwe="CWE-122",
         cve="CVE-2016-6301 类 (realloc 缩容后大写入)",
         title="realloc 缩小后按旧尺寸写入",
         trigger="直接执行 main",
         why="realloc 缩小到 16 字节后仍写入 128 字节, 静态可见尺寸不匹配",
         expect_overflow=True,
         code='''
#include <stdlib.h>
#include <string.h>
int main(void) {
    char src[128];
    memset(src, 'F', sizeof(src));
    char *buf = (char *)malloc(256);
    if (!buf) return -1;
    buf = (char *)realloc(buf, 16);
    if (!buf) return -1;
    memcpy(buf, src, 128);
    free(buf);
    return 0;
}
'''),
    dict(id="tp_08_sprintf_overflow", label="tp", cwe="CWE-122",
         cve="CVE-2018-14634 类 (sprintf 堆溢出)",
         title="sprintf 无界格式化写入堆",
         trigger="直接执行 main",
         why="sprintf 不限制输出长度, 格式化结果超过 16 字节缓冲",
         expect_overflow=True,
         code='''
#include <stdlib.h>
#include <stdio.h>
int main(void) {
    char *buf = (char *)malloc(16);
    if (!buf) return -1;
    sprintf(buf, "%s-%s-%s", "AAAAAAAA", "BBBBBBBB", "CCCCCCCCCCCCCC");
    free(buf);
    return 0;
}
'''),
    dict(id="tp_09_calloc_wrap_overflow", label="tp", cwe="CWE-190",
         cve="CVE-2016-5094 类 (calloc 乘法回绕)",
         title="calloc(n,8) 乘法回绕 + 大写入",
         trigger="./sample 0x20000000",
         why="n*8 无符号回绕得到小分配, 写入 2048 字节越界",
         expect_overflow=True,
         code='''
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    size_t n = argc > 1 ? (size_t)atoi(argv[1]) : 0;
    char src[2048];
    memset(src, 'G', sizeof(src));
    char *buf = (char *)calloc(n, 8);
    if (!buf) return -1;
    memcpy(buf, src, sizeof(src));
    free(buf);
    return 0;
}
'''),
    dict(id="tp_10_struct_field_memcpy", label="tp", cwe="CWE-122",
         cve="CVE-2018-10933 类 (结构体字段越界写)",
         title="memcpy 越过结构体字段边界",
         trigger="直接执行 main",
         why="以结构体指针为目标写 64 字节, 超出字段 name[8] 的边界",
         expect_overflow=True,
         code='''
#include <stdlib.h>
#include <string.h>
typedef struct { char name[8]; int flag; } rec_t;
int main(void) {
    char src[64];
    memset(src, 'H', sizeof(src));
    rec_t *r = (rec_t *)malloc(sizeof(rec_t));
    if (!r) return -1;
    memcpy(r->name, src, 64);
    free(r);
    return 0;
}
'''),
    dict(id="tp_11_recv_overflow", label="tp", cwe="CWE-122",
         cve="CVE-2020-7460 类 (recv 堆溢出)",
         title="read 超过分配大小",
         trigger="无需网络 (fd=0), 读取 1024 字节到 64 字节缓冲",
         why="read 第三参数 1024 大于分配 64, 溢出为静态可证",
         expect_overflow=True,
         code='''
#include <stdlib.h>
#include <unistd.h>
int main(void) {
    int fd = 0;
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    read(fd, buf, 1024);
    free(buf);
    return 0;
}
'''),
    dict(id="tp_12_gets_overflow", label="tp", cwe="CWE-122",
         cve="CVE-2008-1616 类 (gets 堆溢出)",
         title="scanf %s 无界读入堆缓冲",
         trigger="stdin 输入超长串即溢出",
         why="scanf %s 不限制读入长度, 堆缓冲仅 16 字节",
         expect_overflow=True,
         code='''
#include <stdlib.h>
#include <stdio.h>
int main(void) {
    char *buf = (char *)malloc(16);
    if (!buf) return -1;
    scanf("%s", buf);
    free(buf);
    return 0;
}
'''),
    dict(id="tp_13_cross_func_alias", label="tp", cwe="CWE-122",
         cve="CVE-2019-12815 类 (跨函数别名溢出)",
         title="跨函数经参数别名的大写入",
         trigger="直接执行 main",
         why="write_to 接收 malloc(64) 的缓冲区却写入 256 字节",
         expect_overflow=True,
         code='''
#include <stdlib.h>
#include <string.h>
static char src[256];
static void write_to(char *dst) { memcpy(dst, src, 256); }
int main(void) {
    memset(src, 'I', sizeof(src));
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    write_to(buf);
    free(buf);
    return 0;
}
'''),
    dict(id="tp_14_offset_loop_write", label="tp", cwe="CWE-122",
         cve="CVE-2014-1767 类 (偏移越界堆写)",
         title="循环从偏移 0 写满 128 字节到 64 字节缓冲",
         trigger="直接执行 main",
         why="循环写入总量 128 超过分配 64, 无任何边界检查",
         expect_overflow=True,
         code='''
#include <stdlib.h>
int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    int i = 0;
    while (i < 128) { buf[i++] = 'J'; }
    free(buf);
    return 0;
}
'''),
    dict(id="tp_15_conditional_overflow", label="tp", cwe="CWE-122",
         cve="CVE-2023-3269 类 (条件触发堆溢出)",
         title="分支内大写入 (条件触发)",
         trigger="./sample 1 (flag=1 触发溢出)",
         why="flag 可控且分支内写入 128 字节, 分配仅 64 字节",
         expect_overflow=True,
         code='''
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    int flag = argc > 1 ? atoi(argv[1]) : 0;
    char src[128];
    memset(src, 'K', sizeof(src));
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    if (flag) { memcpy(buf, src, 128); }
    free(buf);
    return 0;
}
'''),
]
