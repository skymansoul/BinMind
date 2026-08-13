#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct rec { int id; char name[48]; double score; };
int main(void) {
    struct rec *r = (struct rec *)malloc(sizeof(struct rec));
    if (!r) return 1;
    r->id = 7;
    strcpy(r->name, "alice");        /* 48字节字段内 */
    r->score = 3.5;
    printf("[*] %s\n", r->name);
    free(r);
    return 0;
}
