/* STACK_BOF_11 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

int main(int c,char**v) { char b[16]; strcpy(b,v[1]); return 0; }
