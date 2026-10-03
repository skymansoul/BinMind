/* INT_BOF_08 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

int main(int c,char**v) { size_t n=atoi(v[1]); n*=4; char*b=malloc(n); read(0,b,n*2); free(b); return 0; }
