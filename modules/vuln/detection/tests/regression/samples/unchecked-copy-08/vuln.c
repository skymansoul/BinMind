/* unchecked-copy-08: memcpy未检查长度
 * 类型: taint-unchecked memcpy
 */
#include <string.h>
#include <unistd.h>
typedef struct { unsigned short len; char data[256]; } Pkt;
void parse(Pkt *pkt) {
    char buf[128];
    memcpy(buf, pkt->data, pkt->len);  /* BUG: 若pkt->len>128→溢出 */
}
int main() { Pkt p; read(0, &p, sizeof(p)); parse(&p); return 0; }
