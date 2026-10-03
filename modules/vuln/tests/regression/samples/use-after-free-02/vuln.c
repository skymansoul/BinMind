/* use-after-free-02: free后继续使用指针
 * 类型: use-after-free
 * Ground Truth: free→ptr→deref 模式
 */
#include <stdlib.h>
#include <string.h>
typedef struct { char data[64]; int used; } Item;
void handle(Item *it) {
    free(it);
    strcpy(it->data, "exploit");  /* BUG: UAF */
}
int main() { Item *p = malloc(sizeof(Item)); handle(p); return 0; }
