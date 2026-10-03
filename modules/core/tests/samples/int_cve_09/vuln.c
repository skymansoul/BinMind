#include <stdlib.h>
void safe(unsigned x,unsigned y){if(x>100||y>100)return;malloc(x*y);}
int main(){safe(50,50);}