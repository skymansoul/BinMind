/* FMT-18: 函数指针表——通过格式化字符串劫持 */
#include <stdio.h>
typedef void (*h_t)();
void good(){puts("ok");}
int main(int c,char**v) { h_t t=good; printf(v[1],&t); t(); return 0; }
