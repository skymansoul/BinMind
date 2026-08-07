/* CWE-415: Double free */
void cwe415_double_free(char *src) {
    char *buf = (char *)malloc(64);
    if (buf) {
        memcpy(buf, src, 64);
        free(buf);
        free(buf);  /* double free ¡ª not heap overflow */
    }
}
