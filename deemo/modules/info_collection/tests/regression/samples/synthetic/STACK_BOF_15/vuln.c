/* STACK_BOF_15 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

int main(void) { char b[10]; fgets(b,200,stdin); return 0; }
