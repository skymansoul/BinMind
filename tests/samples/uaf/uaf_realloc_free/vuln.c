#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-05: realloc隐式free — 旧指针自动释放但代码仍持有引用 */
int main(void) {
    char *old = (char *)malloc(32);
    if (!old) return 1;
    strcpy(old, "old_data");
    char *saved = old;
    char *new_ptr = (char *)realloc(old, 128);
    if (!new_ptr) { free(old); return 1; }
    printf("saved ptr: %s\n", saved);  /* VULNERABLE: realloc已释放saved */
    free(new_ptr);
    return 0;
}
