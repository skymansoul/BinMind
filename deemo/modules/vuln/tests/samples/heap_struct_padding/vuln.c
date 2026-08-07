/* 结构体对齐导致的合法 padding 访问 (非漏洞 — 用于测试误报过滤)
 *
 * 场景: malloc(sizeof(struct)) 分配结构体。编译器在结构体尾部
 * 添加 padding 以满足对齐要求。堆访问的偏移落在 padding 区内 —
 * 这在源码层面"越界", 但在二进制层面是编译器生成的合法访问。
 *
 * 测试目标: 分配器模型应识别此访问在 padding 区内, 滤除误报。
 * 这验证 Phase 3 (allocator) 的有效性。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct padded_struct {
    char name[10];    /* 10 bytes */
    int32_t id;       /* 4 bytes */
    /* 编译器自动插入 2 bytes padding → 总大小 16 */
};

static void access_padding(struct padded_struct *ps) {
    char *raw = (char *)ps;
    /* 合法: raw[14] 和 raw[15] 在 padding 区 */
    raw[14] = 0xFF;
    raw[15] = 0xFE;
}

int main(void) {
    struct padded_struct *ps;
    ps = (struct padded_struct *)malloc(sizeof(struct padded_struct));
    if (!ps) return 1;
    memset(ps, 0, sizeof(struct padded_struct));
    access_padding(ps);
    printf("name=%s id=%d\n", ps->name, ps->id);
    free(ps);
    return 0;
}
