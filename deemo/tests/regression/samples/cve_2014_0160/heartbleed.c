/* CVE-2014-0160 — Heartbleed
 * OpenSSL TLS heartbeat read overrun (heap OOB read)
 * 漏洞: memcpy(bp, pl, payload) 中 payload 未经边界检查
 * 编译: gcc -o heartbleed heartbleed.c -lssl -lcrypto (简化演示版)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { int length; char data[64]; } heartbeat_msg;

void process_heartbeat(heartbeat_msg *msg) {
    unsigned int payload_len = (msg->data[0] << 8) | msg->data[1];
    /* BUG: 未检查 payload_len <= 实际数据长度 */
    char *response = (char *)malloc(3 + payload_len);
    response[0] = msg->data[0];
    response[1] = msg->data[1];
    response[2] = msg->data[2];
    memcpy(response + 3, msg->data + 2, payload_len); /* OOB READ */
    free(response);
}

int main(int argc, char **argv) {
    heartbeat_msg msg;
    msg.length = 64;
    memset(msg.data, 0, 64);
    if (argc > 1) {
        msg.data[0] = 0xFF; msg.data[1] = 0xFF; /* payload=65535 > 64 */
    }
    process_heartbeat(&msg);
    return 0;
}
