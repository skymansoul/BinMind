/* HEAP_BOF_13 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

int main(int c,char**v) { char*b=calloc(1,32); memcpy(b,v[1],strlen(v[1])); free(b); return 0; }
