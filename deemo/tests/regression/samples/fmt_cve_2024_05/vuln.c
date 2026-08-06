/* FMT: sprintf with fmt from argv */
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) { char buf[256]; if(argc>1) { sprintf(buf, argv[1]); puts(buf); } return 0; }
