/* FMT: custom logger with fmt injection */
#include <stdio.h>
#include <string.h>
void mylog(const char *lvl, const char *msg) { printf(lvl); printf(": "); printf(msg); }
int main(int argc, char **argv) { if(argc>1) mylog("ERR", argv[1]); return 0; }
