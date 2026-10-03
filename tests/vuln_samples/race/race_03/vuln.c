/* GENERIC-race-double-check CWE-362: 双重检查锁定——检查-加锁之间可能被修改 */
#include <stdlib.h>
static int*ptr; static int init=0;
void lazy_init(){if(!init){ptr=malloc(64);init=1;}}
int main(){lazy_init();free(ptr);return 0;}
