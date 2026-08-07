/* CWE-122: Heap-based Buffer Overflow ¡ª linear index */
void cwe122_linear(int user_idx, char val) {
    char *buf = (char *)malloc(64);
    if (buf) {
        buf[user_idx] = val;  /* user_idx unguarded ¡ª OVERFLOW risk */
        free(buf);
    }
}
