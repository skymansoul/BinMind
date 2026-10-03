#include <stdlib.h>
void vuln(int x){void*p=malloc(64);free(p);if(x<0)free(p);}
int main(){vuln(-1);}