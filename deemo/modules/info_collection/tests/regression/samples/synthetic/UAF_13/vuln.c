/* UAF_13 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

void g(int**p) { free(*p); } int main(void) { int *a=malloc(16); *a=42; printf("%d",*a); g(&a); printf("%d",*a); return 0; }
