#include <stdlib.h>
void safe(){void*p=malloc(64);void*q=malloc(64);free(p);free(q);}
int main(){safe();}