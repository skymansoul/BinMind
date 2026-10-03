/* INT_BOF_07 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

int main(int c,char**v) { int n=atoi(v[1]); char*b=malloc(n*8); memcpy(b,v[2],n*8); free(b); return 0; }
