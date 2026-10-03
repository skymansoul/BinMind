/* SAFE: strncpy 使用 sizeof(buf)-1 限制长度 */
#include <string.h>
void safe_copy(const char *s) {
    char buf[32];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
}
int main(int argc, char **argv) {
    if (argc > 1) safe_copy(argv[1]);
    return 0;
}
