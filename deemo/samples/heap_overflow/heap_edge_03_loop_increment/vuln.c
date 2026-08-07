/* loop writes beyond allocated buffer via index increment */
void edge_loop_overflow(char *src) {
    char *buf = (char *)malloc(64);
    if (buf) {
        for (int i = 0; i < 128; i++) {
            buf[i] = src[i];  /* i reaches 127, buffer only 64 ¡ª OVERFLOW */
        }
        free(buf);
    }
}
