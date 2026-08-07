/* CWE-122: strcpy with attacker-controlled input */
void cwe122_strcpy(char *user_input) {
    char *buf = (char *)malloc(128);
    if (buf) {
        strcpy(buf, user_input);  /* unbounded copy ¡ª OVERFLOW */
        free(buf);
    }
}
