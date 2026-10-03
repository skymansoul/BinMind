#include <stdlib.h>
#include <string.h>
char *sig_ptr;
void simulate_signal() { strcpy(sig_ptr,"signal_uaf"); }
int main() { sig_ptr=malloc(64); free(sig_ptr); simulate_signal(); return 0; }
