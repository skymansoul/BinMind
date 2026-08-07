#include <stdlib.h>
void vuln(){char*b=malloc(72);char c=*(b-24);}
int main(){vuln();}