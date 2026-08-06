/* GENERIC-race-safe-atomic SAFE: 原子操作保护——竞态安全不应检出 */
#include <stdlib.h>
static int refs=0;
void atomic_op(){__sync_fetch_and_add(&refs,1);void*p=malloc(64);free(p);__sync_fetch_and_sub(&refs,1);}
int main(){atomic_op();return 0;}
