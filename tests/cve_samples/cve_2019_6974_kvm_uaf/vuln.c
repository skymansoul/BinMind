/* CVE-2019-6974 — KVM guest UAF via concurrent CPU access / CWE-416 */
#include <stdlib.h>
typedef struct { int refcount; void *page; } kvm_page_t;
void kvm_release_page(kvm_page_t *p) {
    if (--p->refcount <= 0) { free(p->page); free(p); }
    /* BUG: another CPU thread may still access p after refcount hits 0 */
}
int main(void) {
    kvm_page_t *pg = malloc(sizeof(kvm_page_t));
    pg->refcount = 1; pg->page = malloc(4096);
    kvm_release_page(pg); return 0;
}
