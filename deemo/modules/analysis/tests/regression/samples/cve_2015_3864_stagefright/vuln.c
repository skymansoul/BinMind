#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void parse_mp4(const char *data, unsigned int size) {
    if(size < 16) return;
    char *buf = malloc(size - 16); /* underflow if size<16 */
    if(!buf) return;
    memcpy(buf, data+16, size); /* heap overflow */
    printf("%s", buf); free(buf);
}
int main(int a, char **v) { if(a<2) return 1;
    char d[4096]; memset(d, 'B', 4096);
    parse_mp4(d, atoi(v[1])); return 0; }