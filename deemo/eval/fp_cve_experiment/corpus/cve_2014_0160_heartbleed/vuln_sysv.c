/* CVE-2014-0160 Heartbleed 模式还原: heartbeat 请求长度字段
 * payload_len 未与实际缓冲区长度比较, 直接以 payload_len 复制.
 * 真实漏洞为越界读; 此处以等价的越界写(memset)建模同一缺陷.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MAX_PAYLOAD 16

int main(int argc, char **argv) {
    (void)argv;
    char *pl = (char *)malloc(MAX_PAYLOAD);
    if (!pl) return 1;
    memcpy(pl, "ping", 5);
    int payload_len = MAX_PAYLOAD + 32;
    if (argc > 1) payload_len = 65535;
    memset(pl + payload_len, 0, 8);
    printf("%d\n", pl[0]);
    free(pl);
    return 0;
}
