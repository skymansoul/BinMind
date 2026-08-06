/* uaf_08 — 虚函数表劫持 (对象释放后通过伪造vtable调用)
 * CWE-416: vtable指针在free后仍可被覆盖和调用
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
typedef void (*handler_t)(void);
typedef struct { handler_t *vtable; } Obj;
void good() { puts("good"); }
int main() {
    Obj *o = malloc(sizeof(Obj));
    handler_t vt[] = {good};
    o->vtable = vt; free(o);
    o->vtable[0](); /* UAF: 通过悬垂指针调用vtable */
    return 0;
}
