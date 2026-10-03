#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-15: 跨函数UAF — free发生在子函数中, use发生在调用者中 */
static char *global = NULL;

void allocate(void) {
    global = (char *)malloc(100);
    if (global) strcpy(global, "interproc_data");
}
void cleanup(void) {
    if (global) { free(global); global = NULL; }
}
void bad_cleanup(void) {
    if (global) free(global);  /* 释放但不置NULL */
}

int main(int argc, char **argv) {
    allocate();
    if (argc > 1) bad_cleanup();
    else cleanup();
    /* bad_cleanup路径: global已释放但非NULL */
    if (global) printf("interproc: %s\n", global);  /* VULNERABLE if argc>1 */
    if (argc <= 1) free(global);
    return 0;
}
