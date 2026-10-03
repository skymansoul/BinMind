/* VULN: 多次 strcat 累积超出缓冲区 */
#include <string.h>
int main() {
    char buf[32] = {0};
    strcat(buf, "AAAAAAAA");
    strcat(buf, "BBBBBBBB");
    strcat(buf, "CCCCCCCC");
    strcat(buf, "DDDDDDDD");
    strcat(buf, "EEEEEEEE");
    return 0;
}
