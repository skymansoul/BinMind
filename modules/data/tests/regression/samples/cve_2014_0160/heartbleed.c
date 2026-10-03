/* CVE-2014-0160 — OpenSSL Heartbleed (Buffer Over-read)
   Type: buffer_overflow / out-of-bounds read
   Compiled: gcc -O0 heartbleed.c -o heartbleed -lssl -lcrypto

   This is a simplified demonstration of the Heartbleed vulnerability.
   The original bug was in OpenSSL's tls1_process_heartbeat() which
   failed to validate the payload length against the actual received
   data, allowing up to 64KB of server memory to be leaked.

   Detection target: StackOverflowDetector should flag the memcpy
   or custom read as having a length parameter derived from
   user-controlled data without bounds checking. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PAYLOAD 65536

static unsigned char server_memory[MAX_PAYLOAD] = {0};

/* Simulated: receive heartbeat request from network */
typedef struct {
    unsigned int payload_length;   /* claimed by client */
    unsigned char payload_data[256]; /* actual data received */
} HeartbeatRequest;

/* VULNERABLE: trusts payload_length without bounds check */
int tls1_process_heartbeat(HeartbeatRequest *req) {
    unsigned char *response;
    unsigned int payload = req->payload_length;

    /* BUG: payload may be up to 65535, but only 256 bytes received.
       No check: if (payload > sizeof(req->payload_data)) return -1; */
    response = (unsigned char *)malloc(payload + 3);
    if (!response) return -1;

    response[0] = 0x02;  /* TLS heartbeat response type */
    response[1] = (payload >> 8) & 0xFF;
    response[2] = payload & 0xFF;

    /* LEAK: copies 'payload' bytes from server memory starting
       at payload_data offset, but payload_data is only 256 bytes.
       The remaining bytes come from adjacent server_memory. */
    memcpy(response + 3, req->payload_data, payload);

    printf("Heartbeat response: %d bytes\n", payload + 3);
    free(response);
    return 0;
}

int main() {
    HeartbeatRequest req;
    /* Attacker sends payload_length=65535 but only 1 byte of payload_data */
    req.payload_length = 65535;
    memset(req.payload_data, 'A', sizeof(req.payload_data));
    req.payload_data[0] = 'X';

    /* Initialize server memory with simulated secrets */
    for (int i = 0; i < 256; i++)
        server_memory[i] = 'S';  /* secret data */
    memcpy(req.payload_data, server_memory, 256);

    tls1_process_heartbeat(&req);
    return 0;
}
