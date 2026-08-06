/* UAF_12 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

void f(char *s) { char *p=malloc(32); free(p); strcpy(p,s); } int main(int c,char**v) { f(v[1]); return 0; }
