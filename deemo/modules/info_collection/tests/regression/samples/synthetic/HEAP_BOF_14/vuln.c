/* HEAP_BOF_14 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

int main(int c,char**v) { void*p; posix_memalign(&p,16,32); memcpy(p,v[1],strlen(v[1])); free(p); return 0; }
