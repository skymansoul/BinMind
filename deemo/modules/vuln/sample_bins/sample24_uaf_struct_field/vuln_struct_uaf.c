/* sample24: 结构体字段UAF — 释放结构体成员后继续通过结构体访问

 * 漏洞类型: Struct Field UAF
 * CVE映射: CVE-2023-44468 (GStreamer struct field UAF)
 * 触发条件: obj->buf = malloc(); free(obj->buf); 后续通过 obj->buf 访问
 * 测试价值: 结构体字段指针追踪 — uaf_use_chain_tracker 的 field_store 维度
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int refcount;
    char *name;
    unsigned char *data;
    size_t data_len;
} Record;

Record *create_record(const char *name, size_t len) {
    Record *r = (Record *)malloc(sizeof(Record));
    r->refcount = 1;
    r->name = strdup(name);
    r->data = (unsigned char *)malloc(len);
    r->data_len = len;
    memset(r->data, 0x42, len);
    return r;
}

void free_data_only(Record *r) {
    if (r && r->data) {
        free(r->data);
        r->data_len = 0;
        /* 注意: r->data 未置 NULL */
    }
}

void print_record(const Record *r) {
    if (!r) return;
    printf("Record: name=%s, data_len=%zu\n", r->name, r->data_len);
    /* [VULN] 结构体字段UAF: free_data_only 已释放 r->data, 此处仍访问 */
    if (r->data && r->data_len > 0) {
        printf("  first byte: 0x%02x\n", r->data[0]);
    }
}

int main(void) {
    Record *rec = create_record("test", 128);
    print_record(rec);
    free_data_only(rec);
    print_record(rec);  /* UAF via struct field */
    free(rec->name);
    free(rec);
    return 0;
}
