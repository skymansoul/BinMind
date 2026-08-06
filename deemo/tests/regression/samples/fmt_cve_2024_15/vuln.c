/* FMT: binary data as format */
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) { char buf[64]; if(argc>1) { strncpy(buf,argv[1],63); printf(buf); } return 0; }
