/* INT_BOF_09 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

int main(int c,char**v) { int n=atoi(v[1]); if(n<0)n=-n; char*b=malloc(n); memset(b,0,n*2); free(b); return 0; }
