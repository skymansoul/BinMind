/* GENERIC-uaf-callback CWE-416: 回调中释放, 外层继续使用 */
#include <stdlib.h>
typedef void(*cb)(void*);
void df(void*p){free(p);}
void proc(void*o,cb f){f(o);int*x=o;*x=42;}
int main(){int*p=malloc(4);proc(p,df);return 0;}
