/* FMT-004: 格式符与参数不匹配——栈信息泄露
 * 场景: printf("%s: %d -> %s", name, id) — 格式符>参数，泄露栈内容
 * 检测器能力: 格式符计数vs参数计数 → DANGEROUS if spec>args
 * 预期: fmt_spec_count(3) > extra_args(2) → DANGEROUS
 */

#include <stdio.h>

typedef struct {
    int id;
    const char *label;
} Item;

/* BUG: 格式符多于参数——printf会从栈上读额外值 */
void print_item_info(const Item *item) {
    /* "%d: %s [%s]" 需要3个参数，但只给了2个 —— 第三个%s读栈 */
    printf("%d: %s [%s]\n", item->id, item->label);
}

/* BUG: 参数类型不匹配 */
void print_stats(unsigned int hits, unsigned int misses) {
    /* "%lu hits, %lu misses, ratio=%f" — 3个格式符, 2个参数 */
    printf("%lu hits, %lu misses, ratio=%f\n", hits, misses);
}

/* 安全的对照: 格式符==参数 */
void print_safe(const char *name, int age) {
    printf("Name: %s, Age: %d\n", name, age);  /* 2符2参——安全 */
}

int main(void) {
    Item it = {42, "widget"};
    print_item_info(&it);
    print_stats(1000, 50);
    print_safe("Bob", 30);
    return 0;
}
