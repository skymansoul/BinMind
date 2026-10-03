#include <string.h>
#include <stdlib.h>
/* realloc缩小后使用旧size */
void realloc_shrink_test(const char *data, int old_size, int new_size) {
    char *buf = malloc(old_size);
    if (!buf) return;
    memcpy(buf, data, old_size); /* safe: exactly fits */
    buf = realloc(buf, new_size); /* shrink! new_size < old_size */
    if (!buf) return;
    /* VULN: 仍按old_size读取——旧内容已丢失，可能读到相邻chunk */
    memcpy(data, buf, old_size); /* over-read after realloc shrink */
    free(buf);
}
int main() {
    char data_in[512], data_out[512];
    for(int i=0;i<512;i++) data_in[i]='M';
    realloc_shrink_test(data_in, 512, 64);
    return 0;
}
