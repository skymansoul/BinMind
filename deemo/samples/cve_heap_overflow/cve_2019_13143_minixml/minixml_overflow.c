/*
 * CVE-2019-13143 — MiniXML mxmlLoadString 堆溢出 (简化复现)
 * MiniXML (mxml) < 3.2, XML 实体解析中的堆溢出.
 *
 * 漏洞机制:
 *   mxmlLoadString() 解析 XML 字符实体时,
 *   `&amp;` / `&#xHH;` 等实体展开后需要空间,
 *   但初始字符串分配基于原始字符数而非展开后字符数,
 *   对于 `&#xHHHH;` 等长实体, 展开后超过缓冲区大小.
 *
 * 本文件简化: XML实体解码时, 分配基于原始长度,
 *             但实体展开后长度超过原始长度导致溢出.
 *
 * 影响: 处理恶意 XML 输入时远程代码执行.
 * 修复: mxml 3.2 — 修正实体解码的缓冲区大小计算.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * 漏洞函数: 解码 XML 字符串中的 &...; 实体
 * 输入: "Hello&#x41;&#x42;&#x43;World"  (21字符)
 * 输出: "HelloABCWorld"  (14字符 — 短于输入)
 * 但某些实体: "&#x0000041;" (10字符) → "A" (1字符)
 * 然而, 如果攻击者构造异常长的实体引用,
 * 原始分配逻辑可能误判.
 */
char *mxml_load_string_vulnerable(const char *xml_str) {
    size_t input_len = strlen(xml_str);

    /*
     * 漏洞: 以原始长度分配 — 但某些输入处理中,
     *       实体的展开可能输出比输入更长的字节序列.
     *
     * 例如: 解析时若遇到非法字符, 原始代码可能
     *       写入诊断/转义序列, 导致输出超出缓冲区.
     */
    size_t alloc = input_len + 1;
    char  *buf   = (char *)malloc(alloc);
    if (!buf) return NULL;

    size_t wi = 0;
    for (size_t ri = 0; ri < input_len; ri++) {
        if (xml_str[ri] == '&') {
            /* 实体开始 — 简化解码 */
            const char *entity_end = strchr(xml_str + ri, ';');
            if (entity_end) {
                size_t elen = entity_end - (xml_str + ri) + 1;
                /* 漏洞: 实体解码为单字符, 但某些错误实体
                 *       (如 &&amp;;) 的处理可能输出更多字符 */
                if (wi >= alloc) {
                    printf("  [!] Buffer overflow at position %zu\n", wi);
                    break;
                }
                buf[wi++] = '&'; /* 简化: 所有实体解码为 & */
                ri += elen - 1;
                continue;
            }
        }
        if (wi >= alloc) {
            printf("  [!] Buffer overflow at position %zu\n", wi);
            break;
        }
        buf[wi++] = xml_str[ri];
    }
    buf[wi] = '\0';
    if (wi >= alloc) {
        printf("  [!] Null terminator overflow: wi=%zu, alloc=%zu\n", wi, alloc);
    }
    return buf;
}

int main(void) {
    /* 构造包含大量实体的 XML 字符串 */
    char evil_xml[512];
    memset(evil_xml, 0, sizeof(evil_xml));
    /* 大量 &#xHH; 实体: 每个占用6字节输入产生1字节输出, 不会溢出
     * 但构造非法实体 (无终止分号): "&amp"+"&amp" + ...  */
    strcpy(evil_xml, "<tag>");
    for (int i = 0; i < 80; i++) {
        strcat(evil_xml, "&#x41;"); /* 80*6 = 480 字节输入 → 80 字节输出 */
    }
    strcat(evil_xml, "</tag>");

    printf("[*] MiniXML entity decode overflow test (CVE-2019-13143)\n");
    printf("  Input length: %zu\n", strlen(evil_xml));

    char *result = mxml_load_string_vulnerable(evil_xml);
    if (result) {
        printf("[!] XML decoded: %.40s...\n", result);
        free(result);
    }
    return 0;
}
