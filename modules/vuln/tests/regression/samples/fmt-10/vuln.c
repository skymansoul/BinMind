/* FMT-10: 包装函数传递格式化字符串 */
#include <stdio.h>
void wrap(char *f) { printf(f); }
int main(int c,char**v) { wrap(v[1]); return 0; }
