/*
 * heap_dynamic_index — User-Controlled Array Index Heap Overflow
 *
 * This sample tests whether a detector can track dynamic (user-controlled)
 * array indices and detect when they exceed the allocation bounds.
 *
 * The program allocates a 256-byte heap buffer, then writes a value at
 * an index specified by the user via the command line. When the index
 * exceeds 255, the write overflows past the end of the heap chunk.
 *
 * This tests **index-range tracking**: the analyser must model the
 * relationship between the user-supplied index and the buffer size,
 * and flag cases where `user_index >= buffer_size` or `user_index > 255`.
 *
 * Usage: ./vuln <index> <value>
 *   index — integer, the byte offset to write to (0-255 safe, >=256 overflow)
 *   value — integer (0-255), the byte value to write
 *
 * VULNERABLE LINE: buf[user_index] = (char)value;  // when user_index >= 256
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 256

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <index> <value>\n", argv[0]);
        fprintf(stderr, "  index — byte offset (0-255 safe, >=%d overflow)\n", BUF_SIZE);
        fprintf(stderr, "  value — byte value to write (0-255)\n");
        return 1;
    }

    int user_index = atoi(argv[1]);
    int value      = atoi(argv[2]);

    printf("buf_size    = %d\n", BUF_SIZE);
    printf("user_index  = %d\n", user_index);
    printf("value       = %d (0x%02x)\n", value, value & 0xFF);

    /* Allocate a 256-byte heap buffer.                                        */
    char *buf = (char *)malloc(BUF_SIZE);
    if (!buf) { perror("malloc"); return 1; }
    memset(buf, 0x00, BUF_SIZE);

    /*
     * [VULNERABLE] No bounds check on user_index.
     * When user_index >= BUF_SIZE (256), the write overflows past the
     * end of the heap chunk, corrupting adjacent memory.
     *
     * A detector with index-range tracking should flag any write where
     * the index is not provably < BUF_SIZE.
     */
    buf[user_index] = (char)(value & 0xFF);

    if (user_index >= BUF_SIZE) {
        printf("!! HEAP OVERFLOW: buf[%d] = 0x%02x (past end of %d-byte buffer) !!\n",
               user_index, (unsigned char)buf[user_index], BUF_SIZE);
        printf("!! Overflow offset: +%d bytes past allocation boundary.\n",
               user_index - BUF_SIZE + 1);
    } else {
        printf("OK: buf[%d] = 0x%02x (index within %d-byte buffer)\n",
               user_index, (unsigned char)buf[user_index], BUF_SIZE);
    }

    printf("\n=== Buffer histogram (first and last 8 bytes) ===\n");
    printf("buf[0..7]   = ");
    for (int i = 0; i < 8; i++) printf("%02x ", (unsigned char)buf[i]);
    printf("\nbuf[%d..%d] = ", BUF_SIZE - 8, BUF_SIZE - 1);
    for (int i = BUF_SIZE - 8; i < BUF_SIZE; i++)
        printf("%02x ", (unsigned char)buf[i]);
    printf("\n");

    free(buf);
    return 0;
}
