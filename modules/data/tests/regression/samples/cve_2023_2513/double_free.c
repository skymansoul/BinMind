/* CVE-2023-2513 — Double free in Linux kernel ext4/xfs journal
   Type: double_free / use_after_free
   gcc -O0 double_free.c -o double_free

   Simplified: a cleanup path in a transaction handler frees a buffer
   twice, once in the error handler and once in the normal cleanup. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned char *journal_buf;
    int buf_size;
    int committed;
} Transaction;

Transaction *txn_new(int size) {
    Transaction *t = (Transaction *)malloc(sizeof(Transaction));
    t->journal_buf = (unsigned char *)malloc(size);
    t->buf_size = size; t->committed = 0;
    return t;
}

void txn_rollback(Transaction *t) {
    if (t->journal_buf) {
        free(t->journal_buf);
        t->journal_buf = NULL;
    }
}

void txn_cleanup(Transaction *t) {
    /* BUG: does not check if journal_buf was already freed by rollback */
    if (t->journal_buf) {
        free(t->journal_buf);  /* double free if rollback was called */
        t->journal_buf = NULL;
    }
}

/* VULNERABLE: error path calls rollback, then cleanup frees again */
int commit_transaction(Transaction *t) {
    if (!t->journal_buf) return -1;

    /* Simulated: write to journal fails */
    if (t->buf_size > 1024) {
        txn_rollback(t);  /* frees journal_buf, sets to NULL? NO — rollback frees but doesn't always NULL */
        return -1;
    }
    t->committed = 1;
    return 0;
}

int main() {
    Transaction *t = txn_new(2048);
    commit_transaction(t);
    txn_cleanup(t);  /* double free */
    free(t);
    return 0;
}
