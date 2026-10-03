#include <stdio.h>
#include <string.h>
void log_msg(const char *u) { char buf[256];
snprintf(buf,sizeof(buf),"user: "); strncat(buf,u,200);
printf(buf); }
int main(int argc, char **argv) { if(argc<2)return 1;
log_msg(argv[1]); return 0; }
