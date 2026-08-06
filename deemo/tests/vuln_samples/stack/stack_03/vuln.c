/* GENERIC-stack-strcat CWE-121: strcat追加数据溢出栈缓冲区 */
#include <string.h>
void ap(char*s){char b[64]="prefix_";strcat(b,s);}
int main(int c,char**v){ap(c>1?v[1]:"data");return 0;}
