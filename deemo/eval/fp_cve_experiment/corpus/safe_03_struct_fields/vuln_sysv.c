/* 安全: 连续结构体字段赋值, 偏移0..28全部在sizeof内. */
#include <stdlib.h>
#include <stdio.h>

typedef struct {
    int f0, f1, f2, f3, f4, f5, f6, f7;
} my_struct;

int main(void) {
    my_struct *s = (my_struct *)malloc(sizeof(my_struct));
    if (!s) return 1;
    s->f0 = 0; s->f1 = 1; s->f2 = 2; s->f3 = 3;
    s->f4 = 4; s->f5 = 5; s->f6 = 6; s->f7 = 7;
    printf("%d\n", s->f7);
    free(s);
    return 0;
}
