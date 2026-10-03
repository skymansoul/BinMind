/* CVE-2021-34866 — Linux kernel eBPF verifier UAF / CWE-416 */
#include <stdlib.h>
typedef struct { void *insn; int len; } bpf_prog_t;
void free_bpf_prog(bpf_prog_t *p) { free(p->insn); free(p); }
void verify_and_run(bpf_prog_t *p) {
    if (p->len > 4096) { free_bpf_prog(p); return; }
    /* BUG: p freed above but still dereferenced below if len <= 4096? 
       Actually the bug is: free'd in error path then accessed in success path
       by another racing verification thread */
    p->insn = NULL; /* UAF if p was already freed by racing thread */
}
int main(void) {
    bpf_prog_t *p = malloc(sizeof(bpf_prog_t));
    p->insn = malloc(512); p->len = 512;
    verify_and_run(p); return 0;
}
