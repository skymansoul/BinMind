/* GENERIC-scanf CWE-787: scanf %s 向固定缓冲区读入无界数据 */
#include <stdlib.h>
#include <stdio.h>
void rd() { char* b=malloc(32); scanf("%s",b); free(b); }
int main() { rd(); return 0; }
