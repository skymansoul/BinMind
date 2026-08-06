/* GENERIC-uaf-guard SAFE: free前检查并置NULL——安全模式 */
#include <stdlib.h>
void mf(char*p){if(p){free(p);p=NULL;}}
int main(){char*b=malloc(64);mf(b);return 0;}
