/* UAF-001: 寄存器别名传播——间接free后使用原始指针
 * 场景: ptr=alloc() → save ptr to rbx → free(rbx) → use(ptr)
 * uaf_state_machine缺陷: 只匹配mov rdi, reg中reg==ptr的情况
 *   当ptr被mov到rbx后free(rbx)，原有代码无法关联ptr和rbx
 * 别名追踪器能力: 构建mov别名图→传递闭包→识别rbx∈alias(ptr)
 * 预期: 别名追踪器检测到UAF，状态机漏检
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    int id;
    char data[64];
} Record;

void process_record_cleanup(int rec_id) {
    /* alloc: rax → rbx (mov rbx, rax) */
    Record *rec = (Record *)malloc(sizeof(Record));
    if (!rec) return;

    rec->id = rec_id;
    memset(rec->data, 0, sizeof(rec->data));

    /* 别名: 将rec(在rbx)复制到另一个寄存器方便传递
     * rbx → r12 (mov r12, rbx)——建立别名关系 */
    Record *saved = rec;  /* 编译器可能产生 mov saved_reg, rec_reg */

    /* free的参数在rdi: mov rdi, saved_reg → call free
     * 但saved和rec指向同一块内存——别名追踪器应识别 */
    free(saved);

    /* UAF: 通过原始指针rec再次使用——rec∈alias(saved)但已被free */
    printf("record id after free: %d\n", rec->id);  /* UAF here */
}

int main(void) {
    process_record_cleanup(42);
    return 0;
}
