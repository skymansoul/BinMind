#include <stdio.h>
#include <string.h>
void vuln_log(const char *user_input) { char buf[512]; snprintf(buf, sizeof(buf), user_input); printf(buf); printf("
"); }
int main(int argc, char **argv) { vuln_log(argc>1 ? argv[1] : "%x%x%x%s%n"); return 0; }
