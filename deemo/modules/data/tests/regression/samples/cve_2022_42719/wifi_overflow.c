/* CVE-2022-42719 — Linux kernel wifi mac80211 heap overflow
   Type: heap_overflow
   gcc -O0 wifi_overflow.c -o wifi_overflow

   Original: mac80211 driver parsed Multi-Link Probe Request IEs without
   validating the length field against the remaining buffer, allowing
   heap buffer overflow via crafted management frames. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_IE_LEN 256

typedef struct { unsigned char *ies; int ies_len; } ProbeRequest;

int parse_ies(ProbeRequest *req, unsigned char *frame, int frame_len, int ie_offset, int ie_count) {
    req->ies = (unsigned char *)malloc(MAX_IE_LEN);
    req->ies_len = 0;

    for (int i = 0; i < ie_count; i++) {
        int off = ie_offset + i * 4;
        if (off + 4 > frame_len) break;
        int ie_len = (frame[off+2] << 8) | frame[off+3];
        /* BUG: ie_len from attacker-controlled frame, no check against MAX_IE_LEN */
        memcpy(req->ies + req->ies_len, frame + off, ie_len + 4);
        req->ies_len += ie_len + 4;
    }
    return 0;
}

int main() {
    unsigned char frame[512]; memset(frame, 0, 512);
    frame[2] = 0x01; frame[3] = 0x00;  /* ie_len = 256, but repeats 10x → overflow */
    ProbeRequest req = {0};
    parse_ies(&req, frame, 512, 0, 10);
    free(req.ies);
    return 0;
}
