/* GENERIC-stack-scanf CWE-121: scanf %s向栈缓冲区读入无界数据 */
#include <stdio.h>
void rd(){char b[48];scanf("%s",b);}
int main(){rd();return 0;}
