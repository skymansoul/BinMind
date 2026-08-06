/* GENERIC-int-loop-count CWE-190: 循环计数溢出导致无限循环 */
#include <stdlib.h>
void loop_buf(unsigned short n){char*b=malloc(n);for(int i=0;i<n;i++)b[i]=0;free(b);}
int main(){loop_buf(65535);return 0;}
