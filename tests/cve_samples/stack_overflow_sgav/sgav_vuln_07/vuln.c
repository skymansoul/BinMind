/* VULN: read(fd, buf, 256) 但 buf 只有 32 字节 */
#include <unistd.h>
int main() {
    char buf[32];
    read(0, buf, 256);
    return 0;
}
