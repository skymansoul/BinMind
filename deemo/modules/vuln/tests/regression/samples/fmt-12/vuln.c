/* FMT-12: 缓冲区格式化后输出——二次格式化 */
#include <stdio.h>
#include <string.h>
int main(int c,char**v) { char b[256]; snprintf(b,256,v[1]); printf(b); return 0; }
