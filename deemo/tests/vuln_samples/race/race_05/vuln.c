/* GENERIC-race-shared-ptr CWE-362: 共享指针竞态——无锁保护 */
#include <stdlib.h>
static char*gb;
void writer(){gb=malloc(128);}
void reader(){if(gb)gb[0]=65;}
int main(){writer();reader();free(gb);return 0;}
