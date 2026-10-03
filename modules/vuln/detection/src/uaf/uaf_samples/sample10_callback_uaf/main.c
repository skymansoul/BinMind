#include <stdio.h>
#include <stdlib.h>

typedef void (*cb_t)(int *);

static int *global = NULL;
static cb_t saved_cb = NULL;

void my_callback(int *data) {
    *data = 999;  /* UAF: data could be freed */
    printf("callback: %d\n", *data);
}

int main(void) {
    int *data = (int *)malloc(sizeof(int) * 4);
    if (!data) return 1;
    *data = 42;
    global = data;
    saved_cb = my_callback;
    free(global);
    /* UAF: callback uses freed data */
    if (saved_cb) saved_cb(global);
    return 0;
}
