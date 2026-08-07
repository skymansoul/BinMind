/* strcat appends to already-full buffer */
void edge_strcat_overflow(char *input) {
    char *buf = (char *)malloc(128);
    if (buf) {
        strcpy(buf, "fixed_prefix_that_is_very_long_");  /* likely >100 chars */
        strcat(buf, input);  /* unbounded append ¡ª OVERFLOW risk */
        free(buf);
    }
}
