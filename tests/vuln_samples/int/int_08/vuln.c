/* GENERIC-int-add-overflow CWE-190: 无符号加法溢出检测 */
#include <stdlib.h>
void add_buf(size_t a,size_t b){size_t t=a+b;char* m=malloc(t);free(m);}
int main(){add_buf((size_t)-1,10);return 0;}
