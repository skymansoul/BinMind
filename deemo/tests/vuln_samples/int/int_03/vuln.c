/* GENERIC-int-mul-wrap CWE-190: calloc参数乘积溢出 */
#include <stdlib.h>
void*mt(int r,int c){return calloc(r,c);}
int main(){char*p=mt(65536,65536);if(p)free(p);return 0;}
