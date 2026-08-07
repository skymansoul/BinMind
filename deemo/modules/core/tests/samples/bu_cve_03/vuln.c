#include <stdlib.h>
void vuln(){char*b=malloc(256);int*v=(int*)(b-8);*v=0;}
int main(){vuln();}