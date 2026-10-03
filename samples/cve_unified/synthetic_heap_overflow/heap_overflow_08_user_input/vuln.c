/* heap_overflow_08: User-controlled allocation with insufficient size
 * CWE-122: size = atoi(argv[1]); buf = malloc(size); memcpy(buf, argv[2], strlen(argv[2]))
 * When strlen(argv[2]) > size → overflow
 * Pattern: taint source (argv) controls size, but write length is independent
 * Expected: TRUE POSITIVE (requires taint-aware analysis)
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int trigger_user_input_overflow(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <alloc_size> <data>\n", argv[0]);
        return 1;
    }
    size_t alloc_sz = (size_t)atoi(argv[1]);
    size_t data_len = strlen(argv[2]);
    char *buf = (char *)malloc(alloc_sz);
    if (!buf) return -1;
    memcpy(buf, argv[2], data_len);  // OVERFLOW if data_len > alloc_sz
    buf[data_len] = 0;
    printf("%s\n", buf);
    free(buf);
    return 0;
}

int main(int argc, char **argv) {
    return trigger_user_input_overflow(argc, argv);
}
