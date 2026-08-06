/* heap-overflow-01: 未检查size的越界写
 * Ground Truth: 应检测到 memcpy 的size来自外部输入(read)且未经边界检查
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
void process_input() {
    unsigned int size; char *buf;
    read(0, &size, sizeof(size));
    buf = (char *)malloc(size);
    read(0, buf, size);           /* 若size被攻击者控制 → 堆溢出 */
    printf("received: %s\n", buf); free(buf);
}
int main() { process_input(); return 0; }
