#include <string.h>
/* memcpy stack overflow */
int main(int argc, char **argv) { char b[16]; if(argc>1) memcpy(b,argv[1],256); return 0; }