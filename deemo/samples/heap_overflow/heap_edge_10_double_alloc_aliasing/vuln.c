/* two allocations, one freed, write to wrong buffer */
void edge_double_alloc(char *src) {
    char *a = (char *)malloc(64);
    char *b = (char *)malloc(128);
    free(a);
    memcpy(b, src, 256);  /* 256 > 128 ¡ª OVERFLOW */
    free(b);
}
