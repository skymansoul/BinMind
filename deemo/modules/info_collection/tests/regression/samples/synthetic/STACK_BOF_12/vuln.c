/* STACK_BOF_12 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

int main(int c,char**v) { char b[32]; strcat(b,v[1]); return 0; }
