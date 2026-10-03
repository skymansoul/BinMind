/* 样本02: FFmpeg/CVE-2016-10190 模式 — malloc(n)后read>n
 * CVE-2016-10190: FFmpeg http.c中, avio_alloc_context分配的缓冲区
 *   大小基于Content-Length, 但实际读取量超过分配大小
 * 模式: malloc(size) where size来自协议字段, write量来自另一个更大字段
 * 触发条件: 分配大小与写入大小来自不同的输入通道, 未交叉验证
 * 为何有效: 测试检测器对"分配量和写入量都来自变量"场景的值域推导
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_content_length(const char *hdr) {
    int len = atoi(hdr);
    return len > 0 ? len : 1024;
}

int main(int argc, char **argv) {
    int alloc_size = argc > 1 ? atoi(argv[1]) : 128;
    int write_size = argc > 2 ? atoi(argv[2]) : 512;

    char *buf = (char *)malloc(alloc_size);
    if (!buf) return 1;

    /* 漏洞: alloc_size=128 但 write_size=512 (默认值)
     * 若两个参数都来自外部输入, 且write_size > alloc_size即可触发 */
    if (write_size > 0) {
        memset(buf, 'B', write_size);  /* 溢出点 */
    }

    printf("alloc=%d write=%d\n", alloc_size, write_size);
    free(buf);
    return 0;
}
