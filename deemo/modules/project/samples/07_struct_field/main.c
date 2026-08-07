/* 样本07: 结构体字段溢出 — memcpy到结构体中固定大小的字段
 * 模式: 分配struct, 但memcpy到某字段时使用错误的size
 * CVE参考: CVE-2018-1000001 (glibc realpath: PATH_MAX溢出)
 * 触发条件: 源数据 > 字段声明大小
 * 为何有效: 测试检测器对结构体字段边界的感知能力
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAME_LEN 32

struct record {
    int id;
    char name[NAME_LEN];
    int score;
};

int main(int argc, char **argv) {
    struct record *rec = (struct record *)malloc(sizeof(struct record));
    if (!rec) return 1;

    rec->id = 1;

    /* 漏洞: 向name[32]写入超过32字节 */
    const char *input = argc > 1 ? argv[1] :
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBOVERFLOW_DATA_HERE";
    size_t input_len = strlen(input);
    memcpy(rec->name, input, input_len); /* 无边界检查 */

    printf("copied %zu bytes into name[%d]\n", input_len, NAME_LEN);
    free(rec);
    return 0;
}
