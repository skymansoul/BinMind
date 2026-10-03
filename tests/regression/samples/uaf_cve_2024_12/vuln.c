/* UAF ptr arith */
#include <stdio.h>
#include <stdlib.h>
int main() { int *arr=malloc(160); arr[0]=42; free(arr); printf("%d",arr[0]); return 0; }
