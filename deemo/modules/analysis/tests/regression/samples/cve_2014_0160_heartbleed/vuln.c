#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void process_heartbeat(const char *payload, unsigned int plen, unsigned int clen) {
    char *buf = malloc(65536); if(!buf) return;
    memcpy(buf, payload, plen);
    char *resp = malloc(clen);
    memcpy(resp, buf, clen); /* BUG: clen > plen causes heap over-read */
    printf("%.*s", clen, resp); free(buf); free(resp);
}
int main(int a, char **v) { if(a<3) return 1;
    char d[256]; memset(d, 'A', 256);
    process_heartbeat(d, atoi(v[1]), atoi(v[2])); return 0; }