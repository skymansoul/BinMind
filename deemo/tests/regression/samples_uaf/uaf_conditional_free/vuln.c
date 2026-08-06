#include <stdio.h>
#include <stdlib.h>
void process(int flag) { char *buf = malloc(100);
if (flag) free(buf); printf("%s\n", buf); }
int main(int argc, char **argv) { process(argc>1?1:0); return 0; }
