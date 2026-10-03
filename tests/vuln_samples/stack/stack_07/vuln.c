/* GENERIC-stack-read CWE-121: read向栈缓冲区读入超长数据 */
#include <unistd.h>
void rd_fd(){char b[32];read(0,b,256);}
int main(){rd_fd();return 0;}
