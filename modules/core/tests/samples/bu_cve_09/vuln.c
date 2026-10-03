#include <stdlib.h>
void safe(){char*b=malloc(64);char c=*(b+0);}
int main(){safe();}