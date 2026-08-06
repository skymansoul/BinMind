/* GENERIC-race-refcount CWE-362: 引用计数竞态——非原子递减 */
#include <stdlib.h>
static int rc=2;
void release(){if(--rc==0)free(malloc(1));}
int main(){release();release();return 0;}
