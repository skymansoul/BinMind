#include <stdlib.h>
void safe(unsigned long a,unsigned long b){malloc(a+b);}
int main(){safe(500,500);}