#include <string.h>
#include <stdlib.h>
/* 结构体嵌套指针导致的间接堆溢出 */
typedef struct {
    int id;
    int data_len;
    char *data_ptr; /* 指向堆上的可变长度数据 */
} record_t;

void process_record(record_t *rec, const char *new_data, int new_len) {
    rec->data_ptr = malloc(rec->data_len);
    if (!rec->data_ptr) return;
    /* VULN: new_len未与rec->data_len比较 */
    memcpy(rec->data_ptr, new_data, new_len);
    free(rec->data_ptr);
}
int main() {
    record_t rec = {.id=1, .data_len=32, .data_ptr=NULL};
    char data[256]; for(int i=0;i<256;i++) data[i]='O';
    process_record(&rec, data, 256); /* alloc=32, copy=256 */
    return 0;
}
