#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-02: 别名指针UAF — q=p; free(p); use(q) */
typedef struct { int id; char data[64]; } Record;
int main(void) {
    Record *p = (Record *)malloc(sizeof(Record));
    if (!p) return 1;
    p->id = 42;
    char *q = (char *)p;
    free(p);
    printf("alias access: %s\n", q);  /* VULNERABLE: q是悬挂指针 */
    return 0;
}
