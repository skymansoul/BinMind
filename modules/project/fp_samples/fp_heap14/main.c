#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned int pktlen = 0x2000;
    if (argc > 1) pktlen = (unsigned int)atoi(argv[1]);
    char *line = (char *)malloc(0x1000);
    char *recv_buf = (char *)malloc(pktlen);
    if (!line || !recv_buf) return 1;
    memset(recv_buf, 'J', pktlen);
    memcpy(line, recv_buf, pktlen);
    printf("%c\n", line[0]);
    free(line); free(recv_buf);
    return 0;
}
