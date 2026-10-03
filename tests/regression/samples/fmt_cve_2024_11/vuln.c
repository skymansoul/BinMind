/* FMT: snprintf chain */
#include <stdio.h>
int main(int argc, char **argv) { char buf[128]; if(argc>1) { snprintf(buf,128,argv[1],argv[2]?argv[2]:""); printf("%s",buf); } return 0; }
