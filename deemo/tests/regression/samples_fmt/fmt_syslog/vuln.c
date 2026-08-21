#include <stdio.h>
#include <syslog.h>
int main(int argc, char **argv) { if(argc<2)return 1;
openlog("v",LOG_PID,LOG_USER); syslog(LOG_ERR,argv[1]);
closelog(); return 0; }
