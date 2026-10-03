// cve23_mem_region_stack — 内存区域判别
// CVE参考: MEM-REGION-SAFE, 模式: memory_region_stack_write
// 关键: mov [rbp-0x8], rax 是栈写入, 不是堆写入
// 旧方法: 检测到rax持有堆指针 + mov指令→可能误判为堆写入
// 新方法: [rbp-0x8]是栈区域→非堆写入→不报告
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 128

// 辅助函数: 将堆指针保存到栈变量
void save_to_stack(char **ptr_storage, char *heap_ptr) {
    // mov [rbp+0x10], rdx 是栈写入 — 不是堆溢出
    *ptr_storage = heap_ptr;
}

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    char *saved_ptr = NULL;  // 栈变量
    save_to_stack(&saved_ptr, buf);  // 将堆指针存入栈变量

    // 实际写入: 通过saved_ptr间接写入
    memset(saved_ptr, 'S', ALLOC_SIZE);  // 安全: 写入128 ≤ 分配128

    printf("buf=%p, saved=%p, SAFE\n", (void *)buf, (void *)saved_ptr);
    free(buf);
    return 0;
}
