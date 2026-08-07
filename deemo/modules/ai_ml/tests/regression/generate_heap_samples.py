# 批量生成堆溢出测试样本——每个独立目录含源码+Makefile+README
# 运行: python generate_heap_samples.py
# 输出: samples_heap_overflow/ 下的15+个子目录

import os
from pathlib import Path

BASE = Path(__file__).parent / "samples_heap_overflow"

SAMPLES = {
    "CVE-2017-13089_wget_heap": {
        "cve": "CVE-2017-13089",
        "desc": "wget skip_short_body中的堆溢出——malloc(size)->memcpy(buf, data, total_size>size)",
        "vuln_type": "heap_overflow",
        "code": r"""
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
/* CVE-2017-13089: wget HTTP chunked transfer heap overflow */
void process_chunk(int chunk_size, const char *data, int data_len) {
    char *buf = malloc(chunk_size);
    if (!buf) return;
    /* VULN: data_len可能大于chunk_size(HTTP response伪造) */
    memcpy(buf, data, data_len > chunk_size ? data_len : chunk_size);
    free(buf);
}
int main() {
    process_chunk(64, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 128);
    return 0;
}
""",
    },
    "CVE-2020-10713_grub2_heap": {
        "cve": "CVE-2020-10713",
        "desc": "GRUB2 BootHole——EFI变量解析时的堆溢出，malloc(size)<实际数据量",
        "vuln_type": "heap_overflow",
        "code": r"""
#include <string.h>
#include <stdlib.h>
/* CVE-2020-10713: GRUB2 EFI variable parsing heap overflow */
void parse_efi_var(const char *var_data, int var_size) {
    int alloc_size = var_size & 0xFF; /* 仅取低8位——可能过小 */
    char *buf = malloc(alloc_size);
    if (!buf) return;
    memcpy(buf, var_data, var_size);  /* VULN: var_size>>alloc_size */
    free(buf);
}
int main() {
    char data[512]; for(int i=0;i<512;i++) data[i]='A';
    parse_efi_var(data, 512); /* alloc_size=0,实际var_size=512 */
    return 0;
}
""",
    },
    "CVE-2023-38545_curl_socks5_heap": {
        "cve": "CVE-2023-38545",
        "desc": "curl SOCKS5握手时的堆溢出——malloc(hostname_len)→memcpy(过长的hostname)",
        "vuln_type": "heap_overflow",
        "code": r"""
#include <string.h>
#include <stdlib.h>
/* CVE-2023-38545: curl SOCKS5 heap overflow */
void socks5_connect(const char *hostname, unsigned short hostname_len, const char *extra_data, unsigned short extra_len) {
    unsigned short alloc_len = hostname_len;
    if (alloc_len < 255) alloc_len = 255;
    char *buf = malloc(alloc_len);
    if (!buf) return;
    memcpy(buf, hostname, hostname_len);
    /* VULN: extra_data追加时未重新检查总大小 */
    memcpy(buf + hostname_len, extra_data, extra_len);
    free(buf);
}
int main() {
    char host[256]; for(int i=0;i<256;i++) host[i]='B';
    socks5_connect(host, 256, host, 256); /* total=512 > alloc=256 */
    return 0;
}
""",
    },
    "CVE-2018-1160_ntfs3g_heap": {
        "cve": "CVE-2018-1160",
        "desc": "NTFS-3G越界写——NTFS attribute解析时alloc大小<实际数据长度",
        "vuln_type": "heap_overflow",
        "code": r"""
#include <string.h>
#include <stdlib.h>
/* CVE-2018-1160: NTFS-3G attribute heap overflow */
void parse_ntfs_attr(const char *attr_data, int declared_size, int actual_size) {
    char *buf = malloc(declared_size);
    if (!buf) return;
    /* VULN: declared_size < actual_size (NTFS metadata可伪造) */
    memcpy(buf, attr_data, actual_size);
    free(buf);
}
int main() {
    char data[512]; for(int i=0;i<512;i++) data[i]='C';
    parse_ntfs_attr(data, 32, 512);
    return 0;
}
""",
    },
    "CVE-2016-10191_ffmpeg_heap": {
        "cve": "CVE-2016-10191",
        "desc": "FFmpeg RTMP解析堆溢出——malloc(header_size)→实际读取更大的包体",
        "vuln_type": "heap_overflow",
        "code": r"""
#include <string.h>
#include <stdlib.h>
/* CVE-2016-10191: FFmpeg RTMP packet heap overflow */
void rtmp_read_packet(const char *pkt, int hdr_size, int body_size) {
    int alloc = hdr_size + body_size / 4; /* 错误的分配大小 */
    char *buf = malloc(alloc);
    if (!buf) return;
    memcpy(buf, pkt, hdr_size + body_size); /* VULN: body_size未缩小 */
    free(buf);
}
int main() {
    char pkt[1024]; for(int i=0;i<1024;i++) pkt[i]='D';
    rtmp_read_packet(pkt, 16, 512);
    return 0;
}
""",
    },
    "CVE-2022-3602_spider_monkey_heap": {
        "cve": "CVE-2022-3602",
        "desc": "SpiderMonkey JS引擎——类型混淆导致的堆溢出(间接分配不足)",
        "vuln_type": "heap_overflow",
        "code": r"""
#include <string.h>
#include <stdlib.h>
/* CVE-2022-3602: type confusion leading to heap overflow */
struct small_obj { int len; char data[32]; };
struct large_obj { int len; char data[128]; };

void copy_obj_data(void *obj, int type_flag, const char *src, int src_len) {
    int alloc_size = type_flag ? sizeof(struct small_obj) : sizeof(struct large_obj);
    char *buf = malloc(alloc_size);
    if (!buf) return;
    /* VULN: type_flag错误→small obj分配但按large obj写入 */
    int obj_data_offset = type_flag ? 4 : 4; /* field offset */
    memcpy(buf + obj_data_offset, src, src_len);
    free(buf);
}
int main() {
    char src[256]; for(int i=0;i<256;i++) src[i]='E';
    copy_obj_data(NULL, 1, src, 128); /* small alloc(36B) vs 128B copy */
    return 0;
}
""",
    },
    "CVE-2019-20892_netatalk_heap": {
        "cve": "CVE-2019-20892",
        "desc": "Netatalk AppleTalk堆溢出——malloc大小基于用户控制字段但field可溢出",
        "vuln_type": "heap_overflow",
        "code": r"""
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
/* CVE-2019-20892: Netatalk DSI heap overflow */
void dsi_process(const uint8_t *pkt, uint16_t pkt_len) {
    uint16_t claimed = (pkt[0] << 8) | pkt[1]; /* user-controlled size */
    char *buf = malloc(claimed);
    if (!buf) return;
    /* VULN: pkt_len可能小于claimed(提前截断)+buf只够claimed但用pkt_len去copy */
    memcpy(buf, pkt + 2, pkt_len - 2);
    free(buf);
}
int main() {
    uint8_t pkt[512];
    pkt[0] = 0x00; pkt[1] = 0x40; /* claimed=64 */
    for(int i=2;i<512;i++) pkt[i]='F';
    dsi_process(pkt, 512); /* pkt_len=512, but malloc only 64 */
    return 0;
}
""",
    },
    "HEAPOVERFLOW-001_multi_alloc_confusion": {
        "cve": "SYNTHETIC",
        "desc": "多malloc场景下的分配配对混淆——测试约束配对器能否正确关联",
        "vuln_type": "heap_overflow",
        "code": r"""
#include <string.h>
#include <stdlib.h>
/* 多分配场景——测试L1约束配对能否正确匹配malloc和memcpy */
void multi_alloc_test(const char *data, int len) {
    char *safe_buf = malloc(256);
    char *vuln_buf = malloc(32);
    char *safe_buf2 = malloc(512);
    if (!safe_buf || !vuln_buf || !safe_buf2) return;
    memcpy(safe_buf, data, 256);   /* safe: 256 <= 256 */
    memcpy(vuln_buf, data, len);   /* VULN: len可达256, 但只有32 */
    memcpy(safe_buf2, data, 512);  /* safe: 512 <= 512 */
    free(safe_buf); free(vuln_buf); free(safe_buf2);
}
int main() {
    char data[512]; for(int i=0;i<512;i++) data[i]='G';
    multi_alloc_test(data, 256);
    return 0;
}
""",
    },
    "HEAPOVERFLOW-002_alignment_edge_case": {
        "cve": "SYNTHETIC",
        "desc": "对齐边界案例——malloc(32)可用48字节，memcpy(40)被误报但实际安全",
        "vuln_type": "safe_with_alignment",
        "code": r"""
#include <string.h>
#include <stdlib.h>
/* 对齐边界测试——malloc(32)在glibc下实际可用48字节
 * 旧检测器: alloc=32, copy=40 → 误报为溢出
 * 新检测器: usable_size(32)=48, copy=40 → 安全(不应报告) */
void alignment_test(const char *data) {
    char *buf = malloc(32);
    if (!buf) return;
    memcpy(buf, data, 40); /* SAFE: 32→usable=48, 40<48 */
    free(buf);
}
int main() {
    char data[128]; for(int i=0;i<128;i++) data[i]='H';
    alignment_test(data);
    return 0;
}
""",
    },
    "HEAPOVERFLOW-003_true_overflow_alignment_aware": {
        "cve": "SYNTHETIC",
        "desc": "真正溢出但考虑对齐后——malloc(32)可用48，memcpy(64)超出——确认溢出",
        "vuln_type": "heap_overflow",
        "code": r"""
#include <string.h>
#include <stdlib.h>
/* 真正溢出——malloc(32)可用48, memcpy(64)→溢出16字节 */
void true_overflow_test(const char *data) {
    char *buf = malloc(32);
    if (!buf) return;
    memcpy(buf, data, 64); /* VULN: 64 > usable(32)=48 */
    free(buf);
}
int main() {
    char data[128]; for(int i=0;i<128;i++) data[i]='I';
    true_overflow_test(data);
    return 0;
}
""",
    },
    "HEAPOVERFLOW-004_implicit_cast_truncation": {
        "cve": "SYNTHETIC",
        "desc": "隐式类型转换截断——size_t→int截断导致分配过小",
        "vuln_type": "heap_overflow",
        "code": r"""
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
/* 隐式类型截断——64位size_t被截断为32位int */
void truncation_test(const char *data, size_t len) {
    int alloc_len = (int)len; /* 截断! len=0x100000001 → alloc_len=1 */
    char *buf = malloc(alloc_len);
    if (!buf) return;
    memcpy(buf, data, len); /* VULN: len是原始的64位值，远大于alloc_len */
    free(buf);
}
int main() {
    char data[256]; for(int i=0;i<256;i++) data[i]='J';
    truncation_test(data, 256);
    return 0;
}
""",
    },
    "HEAPOVERFLOW-005_strcpy_implicit_overflow": {
        "cve": "SYNTHETIC",
        "desc": "strcpy隐式溢出——strcpy使用隐式大小(到null)，alloc不够",
        "vuln_type": "heap_overflow",
        "code": r"""
#include <string.h>
#include <stdlib.h>
/* strcpy隐式溢出——malloc(16)后strcpy(128字节字符串) */
void strcpy_heap_overflow(const char *input) {
    char *buf = malloc(16);
    if (!buf) return;
    strcpy(buf, input); /* VULN: input比16字节长→堆溢出 */
    free(buf);
}
int main() {
    char data[256]; for(int i=0;i<254;i++) data[i]='K'; data[254]=0;
    strcpy_heap_overflow(data);
    return 0;
}
""",
    },
    "HEAPOVERFLOW-006_calloc_nmemb_size_product": {
        "cve": "SYNTHETIC",
        "desc": "calloc(nmemb, size)——乘积可能因整数溢出而分配不足",
        "vuln_type": "heap_overflow",
        "code": r"""
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
/* calloc整数溢出——nmemb*size可能截断 */
void calloc_overflow(int nmemb, int size, const char *data) {
    /* VULN: nmemb*size可能超出int范围被截断 */
    char *buf = calloc(nmemb, size);
    if (!buf) return;
    int total = nmemb * size; /* 如果nmemb=1000000,size=5000→int溢出 */
    memcpy(buf, data, total);
    free(buf);
}
int main() {
    char data[1024]; for(int i=0;i<1024;i++) data[i]='L';
    calloc_overflow(10000, 5000, data);
    return 0;
}
""",
    },
    "HEAPOVERFLOW-007_realloc_use_after_size": {
        "cve": "SYNTHETIC",
        "desc": "realloc缩小后仍用旧大小——realloc(new_size)后仍memcpy(old_size)",
        "vuln_type": "heap_overflow",
        "code": r"""
#include <string.h>
#include <stdlib.h>
/* realloc缩小后使用旧size */
void realloc_shrink_test(const char *data, int old_size, int new_size) {
    char *buf = malloc(old_size);
    if (!buf) return;
    memcpy(buf, data, old_size); /* safe: exactly fits */
    buf = realloc(buf, new_size); /* shrink! new_size < old_size */
    if (!buf) return;
    /* VULN: 仍按old_size读取——旧内容已丢失，可能读到相邻chunk */
    memcpy(data, buf, old_size); /* over-read after realloc shrink */
    free(buf);
}
int main() {
    char data_in[512], data_out[512];
    for(int i=0;i<512;i++) data_in[i]='M';
    realloc_shrink_test(data_in, 512, 64);
    return 0;
}
""",
    },
    "HEAPOVERFLOW-008_loop_accumulated_overflow": {
        "cve": "SYNTHETIC",
        "desc": "循环累计溢出——每次迭代追加内容，alloc不变",
        "vuln_type": "heap_overflow",
        "code": r"""
#include <string.h>
#include <stdlib.h>
/* 循环内累计写超出分配 */
void loop_accumulate(const char *chunks[4], int n_chunks, int chunk_size) {
    char *buf = malloc(64);
    if (!buf) return;
    int offset = 0;
    for (int i = 0; i < n_chunks; i++) {
        memcpy(buf + offset, chunks[i], chunk_size);
        offset += chunk_size; /* VULN: offset超出64 */
    }
    free(buf);
}
int main() {
    const char *chunks[4];
    char c1[32], c2[32], c3[32], c4[32];
    for(int i=0;i<32;i++){c1[i]='a';c2[i]='b';c3[i]='c';c4[i]='d';}
    chunks[0]=c1;chunks[1]=c2;chunks[2]=c3;chunks[3]=c4;
    loop_accumulate(chunks, 4, 32); /* 32*4=128 > 64 */
    return 0;
}
""",
    },
    "HEAPOVERFLOW-009_memmove_overlap_overflow": {
        "cve": "SYNTHETIC",
        "desc": "memmove在堆上重叠拷贝导致的边界外写",
        "vuln_type": "heap_overflow",
        "code": r"""
#include <string.h>
#include <stdlib.h>
/* memmove在堆缓冲区上的非法偏移 */
void memmove_offset_overflow(const char *data, int len, int offset) {
    char *buf = malloc(len);
    if (!buf) return;
    memcpy(buf, data, len);
    /* VULN: offset可使memmove写到buf之后 */
    memmove(buf + offset, buf, len);
    free(buf);
}
int main() {
    char data[128]; for(int i=0;i<128;i++) data[i]='N';
    memmove_offset_overflow(data, 64, 48); /* src=buf+48, dst=buf+48 → 64B copy从buf[48]开始→超出buf[64] */
    return 0;
}
""",
    },
    "HEAPOVERFLOW-010_struct_field_overflow": {
        "cve": "SYNTHETIC",
        "desc": "结构体字段溢出——通过结构体成员指针写入超出堆分配边界",
        "vuln_type": "heap_overflow",
        "code": r"""
#include <string.h>
#include <stdlib.h>
/* 结构体嵌套指针导致的间接堆溢出 */
typedef struct {
    int id;
    int data_len;
    char *data_ptr; /* 指向堆上的可变长度数据 */
} record_t;

void process_record(record_t *rec, const char *new_data, int new_len) {
    rec->data_ptr = malloc(rec->data_len);
    if (!rec->data_ptr) return;
    /* VULN: new_len未与rec->data_len比较 */
    memcpy(rec->data_ptr, new_data, new_len);
    free(rec->data_ptr);
}
int main() {
    record_t rec = {.id=1, .data_len=32, .data_ptr=NULL};
    char data[256]; for(int i=0;i<256;i++) data[i]='O';
    process_record(&rec, data, 256); /* alloc=32, copy=256 */
    return 0;
}
""",
    },
    "HEAPOVERFLOW-011_sprintf_format_heap": {
        "cve": "SYNTHETIC",
        "desc": "sprintf到堆缓冲区的格式化溢出",
        "vuln_type": "heap_overflow",
        "code": r"""
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
/* sprintf写入堆缓冲区无长度限制 */
void sprintf_heap_test(const char *user_input) {
    char *buf = malloc(32);
    if (!buf) return;
    /* VULN: sprintf无n限制，user_input长度未知 */
    sprintf(buf, "User data: %s", user_input);
    free(buf);
}
int main() {
    char data[256]; for(int i=0;i<254;i++) data[i]='P'; data[254]=0;
    sprintf_heap_test(data);
    return 0;
}
""",
    },
    "HEAPOVERFLOW-012_safe_copy_no_overflow": {
        "cve": "SYNTHETIC",
        "desc": "负样本——memcpy在分配边界内——新检测器不应报告为漏洞",
        "vuln_type": "safe",
        "code": r"""
#include <string.h>
#include <stdlib.h>
/* 负样本——memcpy大小<=malloc大小(经过对齐后)——检测器不应报告 */
void safe_copy_test(const char *data) {
    char *buf = malloc(64);
    if (!buf) return;
    memcpy(buf, data, 32); /* SAFE: 32 < usable(64)=64 */
    free(buf);
    buf = malloc(100);
    if (!buf) return;
    memcpy(buf, data, 100); /* SAFE: 100 <= usable(100)=112 */
    free(buf);
}
int main() {
    char data[128]; for(int i=0;i<128;i++) data[i]='Q';
    safe_copy_test(data);
    return 0;
}
""",
    },
}

def create_sample(name, info):
    d = BASE / name
    d.mkdir(parents=True, exist_ok=True)

    # 源码
    code = info['code'].strip()
    (d / "vuln.c").write_text(code + '\n')

    # Makefile
    makefile = """CC=gcc
CFLAGS=-O0 -g -fno-stack-protector -no-pie -Wno-implicit-function-declaration
TARGET=target

all: $(TARGET)

$(TARGET): vuln.c
\t$(CC) $(CFLAGS) -o $@ $<

clean:
\trm -f $(TARGET)
"""
    (d / "Makefile").write_text(makefile)

    # README
    readme = f"""# {name}
- CVE: {info['cve']}
- 类型: {info['vuln_type']}
- 描述: {info['desc']}
- 测试目标: {'验证检测器能否检出真正的堆溢出' if info['vuln_type'] == 'heap_overflow' else '验证检测器能否正确排除误报'}
"""
    (d / "README.md").write_text(readme)

    print(f"  Created: {name} ({info['cve']})")


def main():
    print(f"Generating {len(SAMPLES)} heap overflow test samples...")
    for name, info in SAMPLES.items():
        create_sample(name, info)
    print(f"\nDone. {len(SAMPLES)} samples in {BASE}")

if __name__ == '__main__':
    main()
