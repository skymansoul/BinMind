/*
 * CVE-2016-10190 模式复刻 — FFmpeg HLS 段处理堆溢出
 * 真实漏洞: FFmpeg mov/hls demuxer 越界读写 (崩溃/潜在 RCE)
 * 触发条件: 段大小字段大于实际数据
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct segment {
    unsigned int data_size;
    unsigned char data[32];
};

/* 复刻 mov demuxer: 读取 size 字段后直接拷贝, 未与缓冲比较 */
int read_segment(struct segment *seg, const unsigned char *stream) {
    seg->data_size = (stream[0] << 24) | (stream[1] << 16) |
                     (stream[2] << 8) | stream[3];   /* 外部可控 */
    memcpy(seg->data, stream + 4, seg->data_size);   /* > 32 越界 */
    return 0;
}

int main(int argc, char **argv) {
    unsigned char stream[64];
    memset(stream, 0, sizeof(stream));
    stream[0] = 0x00; stream[1] = 0x00;
    stream[2] = 0x00; stream[3] = 0x80;   /* size = 128 > 32 */
    struct segment *seg = (struct segment *)malloc(sizeof(struct segment));
    if (!seg) return 1;
    read_segment(seg, stream);
    free(seg);
    return 0;
}
