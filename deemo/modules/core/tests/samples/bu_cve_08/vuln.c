#include <stdlib.h>
void vuln(){char*b=malloc(56);char c=*(b-12);}
int main(){vuln();}