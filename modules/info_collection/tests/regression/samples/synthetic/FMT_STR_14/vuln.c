/* FMT_STR_14 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

int main(int c,char**v) { snprintf((char[256]){},256,v[1]); return 0; }
