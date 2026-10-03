#include <unistd.h>
#include <stdlib.h>
#include <string.h>
int main() { unsigned s; read(0,&s,4); char*p=malloc(s+1); memset(p,0,s+256); free(p); return 0; }
