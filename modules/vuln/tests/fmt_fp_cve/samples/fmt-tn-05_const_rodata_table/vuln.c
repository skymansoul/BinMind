/* 常量模板格式串, 参数经查表传入. */
#include <stdio.h>
static const char *TAG = "info";
int main(void) {
    int n = 7;
    fprintf(stderr, "%s: %d\n", TAG, n);
    return 0;
}
