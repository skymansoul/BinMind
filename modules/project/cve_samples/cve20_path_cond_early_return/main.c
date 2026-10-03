// cve20_path_cond_early_return — 提前返回保护
// CVE参考: CVE-2023-early-ret, 模式: path_condition_early_return
// 关键: cmp+ja+jmp构成size>128则退出的保护
// 旧方法: 无路径条件, size值域不确定→误报
// 新方法: fall-through路径size≤128→DEFINITE_SAFE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 128

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    int write_size = 256;
    // 显式边界检查: >128则退出
    if (write_size > ALLOC_SIZE) {
        free(buf);
        return 0;
    }
    // 此路径: write_size ≤ 128

    memset(buf, 'B', write_size);
    printf("buf=%p, wrote %d <= %d, SAFE\n",
           (void *)buf, write_size, ALLOC_SIZE);
    free(buf);
    return 0;
}
