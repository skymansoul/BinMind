/* VULN: VLA buf[n] + strcpy 无界写入 */
#include <string.h>
#include <stdlib.h>
void vuln(int n, const char *s) {
    char buf[n];
    strcpy(buf, s);
}
int main(int argc, char **argv) {
    vuln(argc>1?atoi(argv[1]):16, argc>2?argv[2]:"");
    return 0;
}
