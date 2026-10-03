/* CVE-2019-11477 — Linux kernel TCP SACK panic (UAF in skb)
   Type: use_after_free
   gcc -O0 uaf_skb.c -o uaf_skb

   Simplified demonstration: use-after-free on a heap-allocated buffer
   that represents a TCP socket buffer (skb). The real vulnerability
   involved integer overflow in SACK sequence calculation leading to
   a UAF on sk_buff in the kernel TCP stack. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int seq_start, seq_end;
    unsigned char *data;
    int data_len;
} SACKBlock;

static SACKBlock *global_skb = NULL;

/* Allocate a socket buffer */
SACKBlock *alloc_skb(int size) {
    SACKBlock *skb = (SACKBlock *)malloc(sizeof(SACKBlock));
    skb->data = (unsigned char *)malloc(size);
    skb->data_len = size;
    memset(skb->data, 0, size);
    return skb;
}

void free_skb(SACKBlock *skb) {
    if (skb) {
        free(skb->data);
        free(skb);
    }
}

/* VULNERABLE: processes SACK after skb was already freed */
int process_sack(SACKBlock *skb) {
    /* Simulated: an error path frees skb earlier */
    if (skb->seq_end < skb->seq_start) {
        free_skb(skb);
        global_skb = NULL;
        return -1;
    }
    /* BUG: subsequent code uses skb->data after it may have been freed */
    unsigned char byte = skb->data[0];  /* UAF if skb was freed above */
    printf("First byte: 0x%02x\n", byte);
    return 0;
}

/* Double free trigger */
int double_free_skb(SACKBlock *skb) {
    free_skb(skb);
    free_skb(skb);  /* double free */
    return 0;
}

int main() {
    SACKBlock *skb = alloc_skb(512);
    skb->seq_start = 100;
    skb->seq_end = 50;  /* triggers error path → free */
    process_sack(skb);  /* UAF */
    return 0;
}
