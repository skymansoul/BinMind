/* UAF-10: 双重释放 via 别名 (double free)
 * CVE: 通用 double-free 模式 (参照 CVE-2014-9319 类堆破坏).
 * 触发: p 与 q 别名指向同一对象; free(p) 后未置空; 再次 free(q)
 *       → 对同一对象二次释放.
 * 为何有效: 指针别名传播需将 q 关联到 p 的对象, 且二次 free 判定
 *       依赖释放点序; 对象未置空故映射保留.
 */
#include <stdio.h>
#include <stdlib.h>

void double_free_via_alias(void) {
    char *p = (char *)malloc(32);
    if (!p) {
        return;
    }
    char *q = p;
    free(p);
    free(q);   /* double free */
}

int main(void) {
    double_free_via_alias();
    return 0;
}
