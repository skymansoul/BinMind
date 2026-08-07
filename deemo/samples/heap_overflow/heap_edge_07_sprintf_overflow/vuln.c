/* sprintf into fixed buffer with variable content */
void edge_sprintf_overflow(char *user_input) {
    char *buf = (char *)malloc(32);
    if (buf) {
        sprintf(buf, "User input: %s", user_input);  /* unbounded ¡ª OVERFLOW */
        free(buf);
    }
}
