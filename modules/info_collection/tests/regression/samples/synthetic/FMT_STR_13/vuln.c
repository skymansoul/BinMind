/* FMT_STR_13 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

int main(int c,char**v) { char b[64]; sprintf(b,v[1]); puts(b); return 0; }
