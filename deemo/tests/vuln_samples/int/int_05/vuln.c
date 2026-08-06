/* GENERIC-int-shift-wrap CWE-190: 左移溢出导致分配大小错误 */
#include <stdlib.h>
void*sa(int n){return malloc(1<<n);}
int main(){char*p=sa(31);free(p);return 0;}
