#include <stdlib.h>
void vuln(){char*b=malloc(80);char c=*(b-48);}
int main(){vuln();}