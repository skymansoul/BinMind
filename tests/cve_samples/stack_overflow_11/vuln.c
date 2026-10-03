#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) { int arr[10], i = argc>1?atoi(argv[1]):9; arr[i] = 42; return 0; }
