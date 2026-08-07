#include <string.h>
#include <stdlib.h>
#include <stdint.h>
/* calloc整数溢出——nmemb*size可能截断 */
void calloc_overflow(int nmemb, int size, const char *data) {
    /* VULN: nmemb*size可能超出int范围被截断 */
    char *buf = calloc(nmemb, size);
    if (!buf) return;
    int total = nmemb * size; /* 如果nmemb=1000000,size=5000→int溢出 */
    memcpy(buf, data, total);
    free(buf);
}
int main() {
    char data[1024]; for(int i=0;i<1024;i++) data[i]='L';
    calloc_overflow(10000, 5000, data);
    return 0;
}
