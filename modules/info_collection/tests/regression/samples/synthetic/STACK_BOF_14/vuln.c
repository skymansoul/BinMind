/* STACK_BOF_14 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

int main(int c,char**v) { char b[8]; memcpy(b,v[1],strlen(v[1])); return 0; }
