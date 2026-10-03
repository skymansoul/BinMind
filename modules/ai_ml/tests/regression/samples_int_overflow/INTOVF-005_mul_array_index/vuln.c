/* INTOVF-005: mul溢出导致数组索引越界——乘积用于数组下标而非分配大小
 * 场景: idx = row * ncols + col; 若row*ncols溢出→idx变小→越界写
 *   与INTOVF-002不同: 此处溢出影响的是索引而非分配大小,
 *   但最终效果相同——越界访问堆内存
 * 检测器能力: imul溢出→结果用于数组索引(mov [base+idx*N])→LIKELY
 * 预期: IntOverflowDeepAnalyzer检测到mul+索引关联, risk>=POSSIBLE
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

typedef struct {
    int rows;
    int cols;
    int *data;
} Matrix;

/* BUG: row*ncols可能溢出→idx变小→写越界 */
int matrix_set(Matrix *m, int row, int col, int val) {
    /* 若rows=65536, cols=65536, row=65535, col=0
     * row*cols=65535*65536=0xFFFE0000(≈4.29G)→32位有符号溢出 */
    int idx = row * m->cols + col;
    if (idx < 0 || idx >= m->rows * m->cols) {
        return -1;  /* 检查了上下界但索引计算本身已溢出 */
    }
    m->data[idx] = val;  /* 若idx计算溢出, 此处写越界 */
    return 0;
}

/* BUG: 变体——乘法用于指针偏移计算 */
int *get_cell(Matrix *m, int row, int col) {
    /* row*cols可能溢出→指针偏移错误 */
    return &m->data[row * m->cols + col];
}

/* 安全对照: 使用64位中间结果 */
int matrix_set_safe(Matrix *m, int row, int col, int val) {
    int64_t idx = (int64_t)row * m->cols + col;
    if (idx < 0 || idx >= (int64_t)m->rows * m->cols) {
        return -1;
    }
    m->data[idx] = val;
    return 0;
}

int main(void) {
    Matrix m = {.rows = 100, .cols = 100,
                .data = (int *)calloc(10000, sizeof(int))};
    if (m.data) {
        matrix_set(&m, 50, 50, 42);
        printf("cell(50,50)=%d\n", m.data[50*100+50]);
        free(m.data);
    }
    return 0;
}
