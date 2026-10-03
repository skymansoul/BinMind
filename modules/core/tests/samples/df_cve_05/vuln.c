#include <stdlib.h>
void vuln(int err){void*p=malloc(64);if(err){free(p);}free(p);}
int main(){vuln(1);}