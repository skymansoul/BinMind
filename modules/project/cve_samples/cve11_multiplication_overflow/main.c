// cve11_multiplication_overflow — 帧溢出: malloc(160)→memset(320), GStreamer帧大小溢出
// CVE参考: CVE-2016-9636, 模式: gstreamer_frame
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o cve11_multiplication_overflow main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 160
#define WRITE_SIZE 320

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 分配160B但写入320B
    // 溢出160B
    memset(buf, 'A', WRITE_SIZE);

    printf("buf=%p, wrote %d into %d-byte alloc\n",
           (void *)buf, WRITE_SIZE, ALLOC_SIZE);
    free(buf);
    return 0;
}
