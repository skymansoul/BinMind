/* realloc shrinks buffer, then write uses original size */
void edge_realloc_shrink(char *data) {
    int orig_size = 256;
    char *buf = (char *)malloc(orig_size);
    char *newbuf = (char *)realloc(buf, 64);
    if (newbuf) {
        memcpy(newbuf, data, orig_size);  /* 256 > 64 ¡ª OVERFLOW */
        free(newbuf);
    }
}
