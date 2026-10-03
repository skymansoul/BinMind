/* SAFE: strcpy 前有 strlen 守卫检查 */
#include <string.h>
void safe_copy(const char *s) {
    char buf[32];
    if (strlen(s) < 32) {
        strcpy(buf, s);
    }
}
int main(int argc, char **argv) {
    if (argc > 1) safe_copy(argv[1]);
    return 0;
}
