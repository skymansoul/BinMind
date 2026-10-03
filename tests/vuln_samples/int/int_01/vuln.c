/* CVE-2016-2177 CWE-190: count*size乘法溢出导致分配过小 */
#include <stdlib.h>
#include <string.h>
void*al(int c,int s){return malloc(c*s);}
int main(){char*p=al(1<<30,4);memcpy(p,"x",(size_t)(1<<30)*4);free(p);return 0;}
