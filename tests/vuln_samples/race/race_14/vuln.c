/* GENERIC-race-safe-mutex SAFE: 互斥锁保护——竞态安全不应检出 */
#include <stdlib.h>
static int locked=0;
void safe_op(){if(!locked){locked=1;void*p=malloc(64);free(p);locked=0;}}
int main(){safe_op();return 0;}
