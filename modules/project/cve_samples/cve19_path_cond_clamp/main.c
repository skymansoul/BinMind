// cve19_path_cond_clamp — 路径条件钳位保护
// CVE参考: CVE-2023-path-cond, 模式: path_condition_clamp
// 关键: static分析必须在cmp/jg分支后应用size≤256约束
// 旧方法(无路径条件): size值域不确定→误报
// 新方法(有路径条件): 分支后size≤256→DEFINITE_SAFE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 256

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 路径条件保护: 若>256则钳位
    int write_size = 512;
    if (write_size > ALLOC_SIZE)
        write_size = ALLOC_SIZE;
    // 路径条件: write_size ≤ 256

    memset(buf, 'A', write_size);
    printf("buf=%p, wrote %d <= %d, SAFE\n",
           (void *)buf, write_size, ALLOC_SIZE);
    free(buf);
    return 0;
}
