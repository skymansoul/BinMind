/* CWE-416: Use-after-free ¡ª not a heap overflow */
void cwe416_uaf(char *src) {
    char *buf = (char *)malloc(64);
    free(buf);
    memcpy(buf, src, 64);  /* UAF ¡ª differential from heap overflow */
}
