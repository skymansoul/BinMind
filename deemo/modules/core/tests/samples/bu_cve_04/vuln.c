#include <stdlib.h>
void vuln(){char*b=malloc(96);char c=*(b-64);}
int main(){vuln();}