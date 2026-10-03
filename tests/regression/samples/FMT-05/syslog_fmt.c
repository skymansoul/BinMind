#include <stdio.h>
/* syslog with user format string */
void syslog(int prio, const char *fmt, ...);
int main(int argc, char **argv) { if(argc>1) syslog(3, argv[1]); return 0; }