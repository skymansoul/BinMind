/* GENERIC-uaf-ioctl CWE-416: ioctl handler中free后继续使用 */
#include <stdlib.h>
void*ctx;
void handle(){free(ctx);int*x=ctx;*x=0;}
int main(){ctx=malloc(256);handle();return 0;}
