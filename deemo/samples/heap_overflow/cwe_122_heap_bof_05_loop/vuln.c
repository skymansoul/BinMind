/* CWE-122: loop write with dynamic bound */
void cwe122_loop(char *src, int count) {
    char *buf = (char *)malloc(64);
    if (buf) {
        for (int i = 0; i < count; i++) {
            buf[i] = src[i];  /* count may exceed 64 ¡ª OVERFLOW */
        }
        free(buf);
    }
}
