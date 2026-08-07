/* 样本08: realloc后使用旧大小的溢出
 * 模式: realloc缩小了分配, 但后续代码仍用旧大小写入
 * CVE参考: CVE-2019-13143 (Mini HTTPD: realloc缩容后溢出)
 * 触发条件: realloc改变大小后, 后续写入使用原始大小
 * 为何有效: 测试检测器对realloc的追踪 — 应更新分配大小绑定
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    size_t old_size = 256;
    size_t new_size = 64;

    char *buf = (char *)malloc(old_size);
    if (!buf) return 1;
    memset(buf, 0, old_size);

    /* 缩小分配: 256→64 */
    buf = (char *)realloc(buf, new_size);
    if (!buf) return 1;

    /* 漏洞: 仍使用old_size写入! */
    memset(buf, 'R', old_size);
    printf("realloc: %zu->%zu, but wrote %zu bytes\n",
           old_size, new_size, old_size);
    free(buf);
    return 0;
}
