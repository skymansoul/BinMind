/* CVE-2021-4034: polkit pkexec 堆溢出 —— 简化: argv 处理溢出 */
#include <stdlib.h>
#include <string.h>
void pkexec_read_args(char **argv, int argc) {
    int total = 0;
    for(int i=0;i<argc;i++) total += strlen(argv[i]);
    char *buf = malloc(total);
    /* BUG: total 可能超过 INT_MAX, malloc(total) 但对 argv 内容做 strcpy 无边界 */
    char *p = buf;
    for(int i=0; i<argc && p-buf < total; i++) {
        strcpy(p, argv[i]);
        p += strlen(argv[i]);
    }
    free(buf);
}
int main() { char *a[]={"A","B","C"}; pkexec_read_args(a,3); return 0; }
