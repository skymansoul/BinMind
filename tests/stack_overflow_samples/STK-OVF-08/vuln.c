#include <unistd.h>
void r(int fd){char t[64];read(fd,t,256);}
int main(){r(0);return 0;}