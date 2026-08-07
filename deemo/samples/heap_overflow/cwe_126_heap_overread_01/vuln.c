/* CWE-126: Heap over-read (Heartbleed pattern) */
void cwe126_overread(char *src, int user_length) {
    char *buf = (char *)malloc(user_length);
    if (buf) {
        memcpy(buf, src, user_length);  /* alloc == write ¡ª over-read, not overflow */
        free(buf);
    }
}
