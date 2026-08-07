/* sample14: 嵌套循环堆溢出 — 多维数组的边界错误
 *
 * 漏洞类型: Heap overflow via nested loop bound error
 * 触发条件: 外层循环和内层循环使用不同的边界,
 *          内层循环的累积写入超出分配大小
 * 测试价值: 嵌套循环的归纳变量追踪, 测试循环感知分析
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void fill_matrix(int rows, int cols, char fill_char) {
    // 分配: rows * cols 字节
    char *matrix = (char *)malloc(rows * cols);
    if (!matrix) return;

    // [VULN] 内层循环写cols+1列 → 每行多1字节
    // 累积溢出 rows 字节
    for (int r = 0; r < rows; r++) {
        for (int c = 0; c <= cols; c++) {  // BUG: <= 而非 <
            matrix[r * cols + c] = fill_char;
        }
    }
    printf("matrix filled\n");
    free(matrix);
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <rows> <cols>\n", argv[0]); return 1; }
    fill_matrix(atoi(argv[1]), atoi(argv[2]), 'X');
    return 0;
}
