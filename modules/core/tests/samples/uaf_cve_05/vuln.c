// CVE-2017-0674: Cross-function UAF
#include <stdlib.h>
#include <string.h>

typedef struct { int id; char name[32]; } Rec;

void process_record(Rec *r) {
    // @uaf_use — r might already be freed by caller
    int x = r->id;
}

Rec* create_record(int id) {
    Rec *r = (Rec*)malloc(sizeof(Rec));  // @uaf_alloc
    r->id = id; return r;
}

int vuln_cross_func_uaf() {
    Rec *rec = create_record(1);
    free(rec);                            // @uaf_free
    process_record(rec);                  // calls use on freed ptr
    return 0;
}
int main() { vuln_cross_func_uaf(); return 0; }