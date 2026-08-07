/*
 * CVE-2020-0796 (SMBGhost) 模式复刻 — SMB 压缩越界写
 * 真实漏洞: srv2!Srv2DecompressData 未校验解压后大小,
 *           越界写至堆, 可 RCE (CVE-2020-0796)
 * 触发条件: 压缩头声明的解压大小超过实际分配缓冲
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct smb_compress_hdr {
    unsigned int orig_size;   /* 原始大小 (外部可控) */
    unsigned int comp_size;   /* 压缩数据大小 */
};

int decompress(struct smb_compress_hdr *hdr, const char *comp_data) {
    /* 缺陷: 直接按 orig_size 分配并解压, 无上限校验 */
    char *out = (char *)malloc(hdr->orig_size);
    if (!out) return -1;
    /* 模拟 LZ 解压: 写入量与 orig_size 一致 */
    memcpy(out, comp_data, hdr->orig_size);   /* orig_size 可=0xFFFF */
    free(out);
    return 0;
}

int main(int argc, char **argv) {
    struct smb_compress_hdr hdr;
    hdr.orig_size = 0xFFFF;                   /* 外部可控 */
    hdr.comp_size = 8;
    char comp[8];
    memset(comp, 0x41, 8);
    decompress(&hdr, comp);                   /* memcpy 64KB 越界读 */
    return 0;
}
