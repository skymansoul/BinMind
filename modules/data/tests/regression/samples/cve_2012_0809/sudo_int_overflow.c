/* CVE-2012-0809 — sudo 1.8.3p1 integer overflow in sudo_debug
   Type: integer_overflow
   gcc -O0 sudo_int_overflow.c -o sudo_int_overflow

   sudo_debug() used an attacker-controlled int for malloc size
   calculation without overflow check. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void sudo_debug(int user_count, const char *data) {
    /* BUG: user_count * 1024 can overflow int, causing malloc(0) */
    int alloc_size = user_count * 1024;
    char *buf = (char *)malloc(alloc_size);
    if (!buf) return;

    /* memcpy with original user_count*1024 bytes → heap overflow */
    memcpy(buf, data, (unsigned int)(user_count * 1024));
    printf("Debug buffer: %d bytes allocated\n", alloc_size);
    free(buf);
}

int main() {
    /* user_count=4194305: 4194305*1024 = 0 (32-bit overflow) */
    char payload[256]; memset(payload, 'D', 256);
    sudo_debug(4194305, payload);
    return 0;
}
