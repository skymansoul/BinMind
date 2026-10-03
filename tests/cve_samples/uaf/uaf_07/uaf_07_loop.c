/* UAF-07: Loop-based use-after-free — free inside loop, use after loop (TP) */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void process(char **items, int n) {
    for (int i = 0; i < n; i++) {
        items[i] = (char *)malloc(32);
        if (items[i]) strcpy(items[i], "item");
    }
    for (int i = 0; i < n; i++) {
        free(items[i]);
    }
    /* BUG: freed pointers still in items[] — use after loop */
    for (int i = 0; i < n; i++) {
        printf("%s\n", items[i]);  /* UAF */
    }
}

int main(void) {
    char *arr[3] = {NULL};
    process(arr, 3);
    return 0;
}
