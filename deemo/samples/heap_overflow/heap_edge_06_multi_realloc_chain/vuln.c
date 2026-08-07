/* chain of reallocs with stale size reference */
void edge_realloc_chain(char *data) {
    int sz = 128;
    char *buf = (char *)malloc(sz);
    buf = (char *)realloc(buf, 64);
    buf = (char *)realloc(buf, 32);
    if (buf) {
        memcpy(buf, data, sz);  /* 128 > 32 ¡ª OVERFLOW */
        free(buf);
    }
}
