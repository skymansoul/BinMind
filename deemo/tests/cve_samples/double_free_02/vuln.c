/* double_free_02 — 条件分支导致双重释放
 * CWE-415: 在if/else分支中重复free同一指针
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
void process(int flag) {
    char *p = malloc(128);
    if (flag) { free(p); }
    free(p); /* flag==1 时双重释放 */
}
int main(int argc, char **argv) {
    process(argc > 1 ? 1 : 0);
    return 0;
}
