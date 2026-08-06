/* CVE-2019-13134 — ImageMagick 堆溢出
 * ReadMATImage 中未检查用户输入的列数, 导致越界写入.
 * 类型: heap_buffer_overflow / CWE-122
 */
#include <stdlib.h>
#include <string.h>
void parse_image(int user_cols, int user_rows, char *pixel_data, int data_len) {
    int expected = user_cols * user_rows * 4;
    char *buf = malloc(expected);  /* 信任用户输入的尺寸 */
    /* BUG: data_len 可能远小于 expected, 导致读越界;
       或者 data_len 远大于 expected, 导致写越界 */
    memcpy(buf, pixel_data, data_len);
    free(buf);
}
int main(void) {
    char data[64]; memset(data, 0, 64);
    parse_image(100, 100, data, 64);  /* 64 < 100*100*4 → 越界 */
    return 0;
}
