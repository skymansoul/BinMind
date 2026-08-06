/* UAF_15 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

int main(void) { int *a=malloc(100); free(a); a[0]=1; return 0; }
