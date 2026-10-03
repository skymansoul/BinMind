/* CVE-2021-3156: sudo Baron Samedit 堆溢出 */
#include <stdlib.h>
#include <string.h>
void sudo_parse_args_size(char *user_args, size_t bufsize) {
    char *buf = malloc(bufsize);
    size_t actual = strlen(user_args);
    /* BUG: actual 可能 > bufsize, 但代码无条件 memcpy actual 字节 */
    memcpy(buf, user_args, actual);
    free(buf);
}
int main() { sudo_parse_args_size("AAAAAAAAAAAA", 10); return 0; }
