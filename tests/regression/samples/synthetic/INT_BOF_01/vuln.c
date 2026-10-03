/* CWE-190: Integer overflow in malloc size calculation.
   n * sizeof(item) can overflow → small allocation → heap overflow on memcpy.
   Pattern seen in CVE-2015-7547 (getaddrinfo), CVE-2019-11477 (TCP SACK). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void process(int count, char *data) {
    size_t alloc_size = count * sizeof(int);  /* may overflow */
    int *buf = malloc(alloc_size);
    if (!buf) return;
    memcpy(buf, data, count * sizeof(int)); /* write may exceed alloc */
    printf("item[0]=%d\n", buf[0]);
    free(buf);
}
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 1073741824; /* large value */
    process(n, "AAAA");
    return 0;
}
