#include <stdlib.h>
void vuln(){char*b=malloc(128);char c=*(b-32);}
int main(){vuln();}