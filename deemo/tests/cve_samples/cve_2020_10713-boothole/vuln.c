/* CVE-2020-10713: BootHole GRUB2 堆溢出 —— 简化: 配置文件解析溢出 */
#include <stdlib.h>
#include <string.h>
void parse_grub_cfg_line(char *line) {
    size_t len = strlen(line);
    char *buf = malloc(len + 1);
    /* BUG: 未预期 len 可能为 0 (空行), malloc(1) 后 strcpy+strcat 追加大量数据 */
    strcpy(buf, line);
    strcat(buf, " extra_padding_that_can_overflow_the_heap_buffer");
    free(buf);
}
int main() { parse_grub_cfg_line("cfg_line=AAAAAAAA"); return 0; }
