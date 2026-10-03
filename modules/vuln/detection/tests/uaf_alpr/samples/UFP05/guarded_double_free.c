
/* 良性: 二次释放被判空守卫阻断. */
#include <stdlib.h>

static int g_flag;

static void release(int *p) {
    free(p);
    if (g_flag) free(p);      /* 守卫, 不执行 */
}

int main(void) {
    int *p = malloc(sizeof(*p));
    release(p);
    return 0;
}
