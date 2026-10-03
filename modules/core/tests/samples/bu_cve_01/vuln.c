#include <stdlib.h>
void vuln(){char*b=malloc(64);char c=*(b-16);}
int main(){vuln();}