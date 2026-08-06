/* GENERIC-uaf-array CWE-416: 数组元素释放后仍被引用 */
#include <stdlib.h>
typedef struct{int id;char*n;}E;
void fa2(E*a,int n){for(int i=0;i<n;i++)free(a[i].n);free(a);}
int main(){E*a=malloc(3*sizeof(E));for(int i=0;i<3;i++){a[i].n=malloc(32);}fa2(a,3);return 0;}
