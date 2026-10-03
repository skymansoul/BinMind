#include <string.h>
/* Off-by-one on stack */
int main(int argc, char **argv) { char b[64]; if(argc>1) { int i; for(i=0;i<=64&&argv[1][i];i++) b[i]=argv[1][i]; } return 0; }