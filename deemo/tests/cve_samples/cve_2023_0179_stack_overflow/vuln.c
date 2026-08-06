/* CVE-2023-0179 — Linux kernel BPF stack buffer overflow / CWE-121 */
#include <string.h>
void bpf_stack_write(char *data, int dlen) {
    char buf[512]; int offset = 0;
    while (dlen > 0) {
        int chunk = dlen > 128 ? 128 : dlen;
        memcpy(buf + offset, data, chunk);
        offset += chunk; dlen -= chunk;
    }
}
int main(void) { char d[1024]; memset(d,'J',1024); bpf_stack_write(d,1024); return 0; }
