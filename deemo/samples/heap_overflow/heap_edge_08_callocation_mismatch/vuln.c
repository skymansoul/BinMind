/* calloc with wrong element count */
void edge_calloc_mismatch(char *src) {
    int count = 16;
    int *buf = (int *)calloc(count, sizeof(int));  /* 16*4=64 bytes */
    if (buf) {
        memcpy(buf, src, 128);  /* 128 > 64 ¡ª OVERFLOW */
        free(buf);
    }
}
