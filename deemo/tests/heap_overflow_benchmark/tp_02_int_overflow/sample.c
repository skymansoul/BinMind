/*
 * TP-02: Integer Overflow in Size Calculation (CWE-190→CWE-122)
 *
 * malloc(a * b) 其中 a*b 溢出为小值 → 实际分配不足
 * 写入时按原始大值计算偏移 → 堆溢出
 *
 * 真实漏洞类比: CVE-2019-13143 (ImageMagick XPM整数溢出)
 */
#include <stdlib.h>
#include <string.h>

int process_image(int width, int height) {
    /* width=65536, height=65536 → 乘积溢出为0 */
    int total = width * height;
    char *buf = (char *)malloc(total); /* 实际分配很小 */

    if (!buf) return -1;

    /* 按原始width写入 → 溢出 */
    for (int i = 0; i < width; i++) {
        buf[i] = 0x41;  /* width=65536 → 写65536B, 远大于实际分配 */
    }

    free(buf);
    return 0;
}

int main(void) {
    return process_image(65536, 65536);
}
