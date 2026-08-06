/* double_free_14 — 回调中双重释放 */
#include <stdio.h>
#include <stdlib.h>
typedef void(*cb_t)(void*);
void process(void*ptr,cb_t cb){cb(ptr);free(ptr);}
void my_cb(void*p){free(p);}
int main(){char*buf=malloc(64);process(buf,my_cb);return 0;}
