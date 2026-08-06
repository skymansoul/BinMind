/* GENERIC-int-neg-alloc CWE-680: 负数作为分配大小隐式转为大正数 */
#include <stdlib.h>
void neg_alloc(int sz){char*b=malloc(sz);if(b)b[0]=0;free(b);}
int main(){neg_alloc(-1);return 0;}
