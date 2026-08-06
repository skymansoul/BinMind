#include <string.h>
/* Loop-based stack overflow */
int main(int argc, char **argv) { char b[64]; int i; if(argc>1) for(i=0;i<256;i++) b[i]=argv[1][i]; return 0; }