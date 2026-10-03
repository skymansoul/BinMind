/* 堆溢出: malloc(64)后写入>64字节 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *buf = (char *)malloc(64);         /* ALLOC 64 */
    if (argc > 1) {
        strcpy(buf, argv[1]);               /* OVERFLOW if len(argv[1]) > 64 */
    }
    printf("%s\n", buf);
    free(buf);
    return 0;
}
