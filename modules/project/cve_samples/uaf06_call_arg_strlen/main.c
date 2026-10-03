// uaf06_call_arg_strlen — 解引用函数UAF
// CVE参考: CVE-UAF-CALL-DEREF, 模式: uaf_call_arg_deref
// 检测目标: 悬挂指针传给strlen等解引用函数
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    strcpy(buf, "test_data");
    free(buf);
    // UAF: strlen读取已释放的指针
    size_t len = strlen(buf);
    printf("UAF strlen: len=%zu\n", len);
    return 0;
}
