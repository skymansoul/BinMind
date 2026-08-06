/* STACK_BOF_13 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

int main(void) { char b[20]; int n=read(0,b,100); return 0; }
