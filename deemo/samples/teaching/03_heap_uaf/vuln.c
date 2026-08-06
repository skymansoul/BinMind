/*
 * 教学样本 #3: Heap Use-After-Free
 *
 * 漏洞: free(chunk) 后指针未置 NULL，后续通过悬空指针写入。
 * 编译: gcc -o vuln vuln.c
 *
 * 利用思路: free → allocate new chunk → UAF write → 控制函数指针
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char data[32];
    void (*callback)(void);
} Object;

void win() {
    printf("flag{uaf_exploit_success}\n");
}

void normal() {
    printf("normal operation\n");
}

int main() {
    Object *obj = malloc(sizeof(Object));
    obj->callback = normal;
    strcpy(obj->data, "test data");
    obj->callback();

    free(obj);
    /* 漏洞: obj 指针未置 NULL */

    /* 模拟: 新分配覆盖已释放内存 */
    char *fake = malloc(sizeof(Object));
    memset(fake, 0, sizeof(Object));
    /* 若堆分配器重用同一块内存，fake 和 obj 指向同一地址 */
    *(void **)(fake + 32) = win;  /* 覆盖 callback 指针 */

    obj->callback();  /* UAF: 调用已被覆盖的函数指针 */
    free(fake);
    return 0;
}
