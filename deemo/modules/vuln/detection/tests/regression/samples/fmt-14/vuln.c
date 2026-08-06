/* FMT-14: 日志宏展开的格式化字符串 */
#include <stdio.h>
#define LOG(fmt,...) printf(fmt,##__VA_ARGS__)
int main(int c,char**v) { LOG(v[1]); return 0; }
