/* uaf_04 — 线程间UAF (简化版: 函数指针表在free后被调用)
 * CWE-416: 虚函数表在对象释放后仍被调用
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
typedef struct { void (*handler)(void); } Object;
void safe_handler() { printf("safe\n"); }
void process() {
    Object *obj = malloc(sizeof(Object));
    obj->handler = safe_handler;
    free(obj);
    obj->handler(); /* UAF: 通过悬垂指针调用函数 */
}
int main() { process(); return 0; }
