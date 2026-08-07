#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned int payload = 0x800;
    if (argc > 1) payload = (unsigned int)atoi(argv[1]);
    unsigned int hdr = 16;
    char *pkt = (char *)malloc(hdr + payload);
    char *pls = (char *)malloc(payload);
    if (!pkt || !pls) return 1;
    memset(pls, 'D', payload);
    memcpy(pkt + hdr, pls, payload + 1);
    printf("%c\n", pkt[0]);
    free(pkt); free(pls);
    return 0;
}
