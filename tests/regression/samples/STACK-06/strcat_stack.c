#include <string.h>
/* strcat stack overflow */
int main(int argc, char **argv) { char b[32]=""; if(argc>1) strcat(b,argv[1]); return 0; }