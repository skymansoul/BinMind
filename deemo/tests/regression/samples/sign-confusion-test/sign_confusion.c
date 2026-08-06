/* Signed/unsigned comparison confusion
 * gcc -g -O0 -o vuln sign_confusion.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void check_and_copy(int user_len, char *data) {
    size_t max = 4096;
    if (user_len < max) { /* signed compare: user_len=-1 passes */
        char *buf = malloc(user_len);
        memcpy(buf, data, user_len); /* huge copy if user_len was -1 */
        free(buf);
    }
}
int main(int argc, char **argv) {
    if(argc<3) return 1;
    check_and_copy(atoi(argv[1]), argv[2]);
    return 0;
}