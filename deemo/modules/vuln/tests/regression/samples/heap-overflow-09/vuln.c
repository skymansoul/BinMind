/* heap-overflow-09: 只有一条路径有保护, 另一条无保护
 * Ground Truth: 应区分protect路径和无保护路径
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
void process(int mode) {
    unsigned int size; char *buf;
    read(0, &size, sizeof(size));
    buf = malloc(256);
    if (mode == 0) {
        if (size > 256) size = 256;  /* 有保护 */
    }
    /* BUG: mode!=0时无保护, size可>256 */
    read(0, buf, size);
    free(buf);
}
int main(int argc, char**argv) { process(argc); return 0; }
