/* SAFE: snprintf 使用 sizeof(buf) 限制写入 */
#include <stdio.h>
void safe_fmt(const char *s) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%s", s);
}
int main(int argc, char **argv) {
    if (argc > 1) safe_fmt(argv[1]);
    return 0;
}
