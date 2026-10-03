#include <stdlib.h>
void safe(){void*p=malloc(64);free(p);}
int main(){safe();}