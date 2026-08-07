#include <stdlib.h>
void vuln(){char*b=malloc(48);char c=b[-4];}
int main(){vuln();}