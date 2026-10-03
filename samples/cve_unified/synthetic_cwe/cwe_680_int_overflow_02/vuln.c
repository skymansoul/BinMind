/* CWE-680: Integer overflow in size calculation */
#include <stdlib.h>
#include <string.h>

void cwe680_size_calc(char *data, int width, int height) {
    int size = width * height;  /* may overflow */
    char *buf = (char *)malloc(size);
    if (buf) {
        memcpy(buf, data, width * height * 4);  /* width*height*4 may differ from size */
        free(buf);
    }
}

int main(void) {
    static char data[16];
    cwe680_size_calc(data, 1000, 1000);  /* width*height overflows int */
    return 0;
}
