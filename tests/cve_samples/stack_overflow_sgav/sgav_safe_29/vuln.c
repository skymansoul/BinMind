/* SAFE: recv 限制接收大小 */
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
void safe_recv(int sock) {
    char buf[64];
    recv(sock, buf, sizeof(buf) - 1, 0);
}
int main() { safe_recv(0); return 0; }
