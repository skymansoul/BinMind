/* FMT_STR_15 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

int main(int c,char**v) { syslog(LOG_USER,v[1]); return 0; }
