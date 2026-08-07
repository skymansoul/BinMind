/* CWE-190: Integer overflow ¡ú small allocation ¡ú heap overflow */
void cwe190_intof(int n) {
    int alloc_sz = n * 4;  /* may wrap to small value */
    char *buf = (char *)malloc(alloc_sz);
    if (buf) {
        memcpy(buf, src, n * 8);  /* write > alloc if n*4 overflowed */
        free(buf);
    }
}
