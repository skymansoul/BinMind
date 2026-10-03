/* FMT: err() family */
#include <stdio.h>
#include <err.h>
int main(int argc, char **argv) { if(argc>1) err(1, argv[1]); return 0; }
