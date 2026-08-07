#include <string.h>
#include <stdlib.h>
#include <stdio.h>
/* sprintf写入堆缓冲区无长度限制 */
void sprintf_heap_test(const char *user_input) {
    char *buf = malloc(32);
    if (!buf) return;
    /* VULN: sprintf无n限制，user_input长度未知 */
    sprintf(buf, "User data: %s", user_input);
    free(buf);
}
int main() {
    char data[256]; for(int i=0;i<254;i++) data[i]='P'; data[254]=0;
    sprintf_heap_test(data);
    return 0;
}
