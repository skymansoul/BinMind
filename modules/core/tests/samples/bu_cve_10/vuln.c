#include <stdlib.h>
void safe(){char*b=malloc(128);char c=*(b+16);}
int main(){safe();}