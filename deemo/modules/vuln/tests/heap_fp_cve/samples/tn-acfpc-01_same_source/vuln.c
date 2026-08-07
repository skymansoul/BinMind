/* TN 对照 1: 同源共变模式 — p=malloc(len); memcpy(p, q, len).
   写入量与分配量源自同一变量 len, 共变无越界. 旧版检测器对
   动态 size 保守报疑似, 形成 FP; ACFPC 参数耦合链判定 COUPLED 压制. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    size_t len;
    char *buf;
    char *src;

    if (argc < 2) {
        return 0;
    }
    len = strlen(argv[1]);
    buf = (char *)malloc(len);
    src = (char *)malloc(len);
    if (!buf || !src) {
        return 1;
    }
    memcpy(src, argv[1], len);
    memcpy(buf, src, len);
    printf("%s\n", buf);
    free(buf);
    free(src);
    return 0;
}
