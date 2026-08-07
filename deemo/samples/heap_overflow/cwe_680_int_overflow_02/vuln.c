/* CWE-680: Integer overflow in size calculation */
void cwe680_size_calc(int width, int height) {
    int size = width * height;  /* may overflow */
    char *buf = (char *)malloc(size);
    if (buf) {
        memcpy(buf, data, width * height * 4);  /* width*height*4 may differ from size */
        free(buf);
    }
}
