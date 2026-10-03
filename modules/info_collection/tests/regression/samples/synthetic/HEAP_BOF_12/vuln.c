/* HEAP_BOF_12 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

int main(int c,char**v) { char*b=malloc(16); strncpy(b,v[1],256); free(b); return 0; }
