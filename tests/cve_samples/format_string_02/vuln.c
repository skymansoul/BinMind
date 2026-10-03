/* format_string_02 — fprintf 通过包装函数间接使用可变参数
 * 对应 CWE-134: 用户输入间接流到格式化函数
 * 编译: gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <string.h>

void write_log(FILE *fp, const char *fmt) {
    fprintf(fp, fmt);  /* 危险: fmt 来自调用者的用户输入 */
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    write_log(stderr, argv[1]);
    return 0;
}
