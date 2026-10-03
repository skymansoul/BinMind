#include <stdio.h>
/* snprintf with wrong size */
int main(int argc, char **argv) { char b[32]; if(argc>1) snprintf(b,256,"%s",argv[1]); return 0; }