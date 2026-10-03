/* GENERIC-uaf-double-ptr CWE-416: 双重指针释放后解引用 */
#include <stdlib.h>
void dp(char**pp){free(*pp);**pp='X';}
int main(){char*b=malloc(64);*b='A';dp(&b);return 0;}
