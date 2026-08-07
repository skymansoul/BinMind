/* CWE-122: memcpy with attacker-controlled size */
void cwe122_memcpy(char *src, int user_len) {
    char *buf = (char *)malloc(64);
    if (buf && user_len > 0) {
        memcpy(buf, src, user_len);  /* user_len may exceed 64 ¡ª OVERFLOW */
        free(buf);
    }
}
