/* HEAP_BOF_15 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

int main(void) { char*b=malloc(1); b=realloc(b,2); memset(b,0x41,256); free(b); return 0; }
