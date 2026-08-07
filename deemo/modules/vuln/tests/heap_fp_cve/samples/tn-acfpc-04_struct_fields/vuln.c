/* TN 对照 4: 结构体字段访问模式 — malloc(64) 后多个字段写入,
   每个字段偏移+大小均在块内. 启发式检测器把字段写误判为越界
   (偏移+大小 与 分配大小 的朴素比较), 形成典型 FP. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct record {
    char name[32];
    int id;
    long flag;
};

int main(void) {
    struct record *rec;

    rec = (struct record *)malloc(64);
    if (!rec) {
        return 1;
    }
    memset(rec->name, 0, 32);
    rec->id = 7;
    rec->flag = 1;
    printf("%s %d %ld\n", rec->name, rec->id, rec->flag);
    free(rec);
    return 0;
}
