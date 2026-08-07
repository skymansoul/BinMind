/*
 * sample_09 — 函数指针表堆溢出 (间接控制流劫持).
 *
 * 漏洞: 堆上的函数指针表在缓冲区之后, 溢出覆盖函数指针.
 * 这是经典的堆利用技术 — 覆盖 vtable/函数指针实现任意代码执行.
 *
 * CWE-122 → CWE-123 (Write-what-where).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*handler_t)(void);

void safe_handler(void) { printf("safe handler\n"); }
void evil_handler(void) { printf("EVIL HANDLER — would be shellcode\n"); }

typedef struct {
    char buf[32];
    handler_t callback;
} ObjWithCallback;

int main(void) {
    ObjWithCallback *obj = (ObjWithCallback *)malloc(sizeof(ObjWithCallback));
    if (!obj) return 1;

    obj->callback = safe_handler;

    /* 溢出: 写入超过 buf[32] 的边界, 覆盖 callback 指针 */
    memset(obj->buf, 'A', 64);

    /* callback 已被覆盖 — 调用可能 crash 或劫持控制流 */
    obj->callback();

    free(obj);
    return 0;
}
