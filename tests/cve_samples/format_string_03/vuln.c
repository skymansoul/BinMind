#include <stdio.h>
#include <stdlib.h>
void log_user(const char *msg) { printf(msg); }
int main(int argc, char **argv) { log_user(argc>1?argv[1]:"test"); return 0; }
