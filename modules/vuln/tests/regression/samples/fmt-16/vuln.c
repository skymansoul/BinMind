#include <stdio.h>
#include <unistd.h>
int main() { char f[64]; read(0,f,63); fprintf(stderr,"%s",f); return 0; }
