/* INT_BOF_10 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

int main(int c,char**v) { unsigned u=atoi(v[1]); u+=4294967295; char*b=malloc(u); memcpy(b,v[2],atoi(v[3])); free(b); return 0; }
