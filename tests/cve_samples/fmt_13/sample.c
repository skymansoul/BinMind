#include <stdio.h>
#include <string.h>
void grpc_log(char*method){printf(method);}
int main(int c,char**v){if(c>1)grpc_log(v[1]);return 0;}