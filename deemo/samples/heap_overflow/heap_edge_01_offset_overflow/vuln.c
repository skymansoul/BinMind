/* malloc(64) + memcpy(buf+32, src, 48) = writes buf[32..79], overflows at 64 */
void edge_offset_overflow(char *src) {
    char *buf = (char *)malloc(64);
    if (buf) {
        memcpy(buf + 32, src, 48);  /* 32+48=80 > 64 ¡ª OVERFLOW */
        free(buf);
    }
}
