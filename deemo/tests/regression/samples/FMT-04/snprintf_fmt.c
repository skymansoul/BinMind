#include <stdio.h>
/* snprintf with user-controlled format */
int main(int argc, char **argv) { char b[64]; if(argc>1) snprintf(b,64,argv[1]); return 0; }