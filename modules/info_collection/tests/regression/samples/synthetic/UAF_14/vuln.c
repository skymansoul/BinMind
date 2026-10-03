/* UAF_14 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

int main(void) { char *p=malloc(10),*q=p; free(p); puts(q); return 0; }
