/*
 * CVE-2017-5638 模式复刻 — 内容类型解析堆溢出
 * 真实漏洞: Apache Struts2 上传解析器对畸形 Content-Type
 *           引发 OGNL 注入 → RCE; 底层是解析缓冲的越界写
 * 触发条件: 长 Content-Type 头 (无长度校验的 strcpy)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CT 64

char *parse_content_type(const char *raw) {
    char *ct = (char *)malloc(MAX_CT);
    if (!ct) return NULL;
    strcpy(ct, raw);      /* 缺陷: raw 长度无校验 */
    return ct;
}

int main(int argc, char **argv) {
    char attack[256];
    memset(attack, 'A', 200);
    attack[200] = 0;      /* 200B > 64B 缓冲 */
    /* 复刻 OGNL payload 头: %{(#_='multipart/form-data').(#dm=...)} */
    strcpy(attack, "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}");
    char *ct = parse_content_type(attack);
    if (ct) free(ct);
    return 0;
}
