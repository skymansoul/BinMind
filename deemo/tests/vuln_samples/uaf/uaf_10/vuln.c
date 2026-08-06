/* GENERIC-uaf-reuse-var CWE-416: 同一变量名重新分配但不改值 */
#include <stdlib.h>
void rv(){char*p=malloc(64);free(p);p=malloc(128);if(p)p[0]='Y';free(p);}
int main(){rv();return 0;}
