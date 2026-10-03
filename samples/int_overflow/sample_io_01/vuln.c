/* CWE-190: Integer overflow in malloc(n * sizeof(int))
 * n comes from user input (atoi(argv[1])).
 * n=0x40000001 → n*4 wraps to 4 → heap overflow via subsequent memset.
 * EXPECT: TP (integer overflow leading to heap buffer overflow)
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    int n = atoi(argv[1]);
    int *buf = (int*)malloc(n * sizeof(int)); /* overflow: n*4 may wrap */
    if (!buf) return 1;
    memset(buf, 0, n * sizeof(int)); /* writes beyond allocation if wrapped */
    free(buf);
    return 0;
}
