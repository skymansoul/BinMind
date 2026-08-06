/* FMT-8: %n写入——通过可控格式字符串写任意地址 */
#include <stdio.h>
int main(int c,char**v) { int x=0; printf(v[1],&x); return 0; }
