/* calloc分配后溢出: nmemb*size计算错误
 * 预期: 检测器处理calloc的乘积语义
 */
#include <stdlib.h>
#include <string.h>

int main() {
    int n = 4, m = 16;  /* 乘积=64 */
    char *p = (char*)calloc(n, m);
    /* n被覆盖为更大值 */
    n = 100;
    memcpy(p, "data", n);  /* n*m > 64 (n含义已变, 但buf仅64) */
    free(p);
    return 0;
}
