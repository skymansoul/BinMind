/*
 * CVE-2016-10190 — FFmpeg http.c heap overflow
 *
 * Description: The `http_read_stream` function does not properly validate
 * the `size` parameter before allocating and reading data. A malicious
 * HTTP server can send a large chunk size causing a heap buffer overflow.
 *
 * Pattern: malloc(user_controlled_size) + memcpy with same size → appears safe
 * BUT the actual data exceeds the allocated size because size is truncated.
 *
 * Detection challenge: size parameter from network → tainted,
 * but also gets size_t truncation before malloc → mismatch.
 *
 * Minimized reproduction:
 *   size = get_controlled_size();  // returns uint64_t
 *   truncated = (uint32_t)size;     // implicit truncation in libavformat
 *   buf = malloc(truncated);
 *   read_data(buf, size);           // reads original size → overflow!
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long long g_controlled_size = 0x100000001ULL;

static unsigned long long get_controlled_size(void) {
    return g_controlled_size;  // simulated: attacker controlled
}

int main(void) {
    unsigned long long size = get_controlled_size();
    unsigned int truncated = (unsigned int)size;  // truncation to 32-bit
    char *buf = (char *)malloc(truncated);  // allocates 1 byte (0x100000001 & 0xFFFFFFFF = 1)

    if (buf) {
        // Vulnerability: memcpy uses original 64-bit size (0x100000001)
        // but buffer only has 1 byte → massive heap overflow
        memset(buf, 0x41, (size_t)size);  // HEAP OVERFLOW
        printf("CVE-2016-10190: overflow attempted (size=%llu, truncated=%u)\n",
               size, truncated);
        free(buf);
    }
    return 0;
}
