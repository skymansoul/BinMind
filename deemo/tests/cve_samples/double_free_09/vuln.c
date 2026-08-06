/* double_free_09 — atexit注册的函数中重复释放 */
#include <stdio.h>
#include <stdlib.h>
char*gp=NULL;
void cleanup(){free(gp);}
int main(){gp=malloc(128);atexit(cleanup);free(gp);return 0;}
