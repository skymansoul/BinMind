#include <sys/socket.h>
/* recv stack overflow */
int main() { char b[32]; recv(0,b,256,0); return 0; }