#include <syslog.h>
int main(int c,char**v){if(c>1)syslog(LOG_INFO,v[1]);return 0;}