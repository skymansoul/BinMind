/* CVE-2017-1000364 — Linux kernel stack overflow via execve / CWE-121 */
#include <string.h>
#include <stdlib.h>
void setup_arg_pages(char **argv, int argc) {
    char arg_buf[512]; int pos = 0;
    for (int i = 0; i < argc; i++) { /* BUG: total size unchecked */
        int l = strlen(argv[i]);
        memcpy(arg_buf + pos, argv[i], l); pos += l;
    }
}
int main(void) { char *a[4]={"AAAA","BBBB","CCCC","DDDD"}; setup_arg_pages(a,4); return 0; }
