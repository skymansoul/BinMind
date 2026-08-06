#include <stdlib.h>
/* Classic direct UAF: free then use */
int main() { char *p=malloc(64); free(p); p[0]='A'; return 0; }