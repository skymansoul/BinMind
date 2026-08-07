/* guard checks one bound but write uses another variable */
void edge_partial_guard(int idx, int size, char val) {
    char *buf = (char *)malloc(64);
    if (buf && idx < 64) {
        buf[size] = val;  /* size is unguarded ¡ª could overflow */
    }
    free(buf);
}
