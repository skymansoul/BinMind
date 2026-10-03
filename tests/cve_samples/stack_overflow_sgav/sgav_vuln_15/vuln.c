/* VULN: sscanf(src, "%s", buf) 无界写入 */
#include <stdio.h>
#include <string.h>
void vuln(const char *input) {
    char buf[32];
    sscanf(input, "%s", buf);
}
int main(int argc, char **argv) {
    if (argc > 1) vuln(argv[1]);
    return 0;
}
