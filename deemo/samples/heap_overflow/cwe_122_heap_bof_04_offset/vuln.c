/* CWE-122: pointer offset + computed write length */
void cwe122_offset(char *src, int offset, int len) {
    char *buf = (char *)malloc(128);
    if (buf) {
        memcpy(buf + offset, src, len);  /* offset+len may exceed 128 */
        free(buf);
    }
}
