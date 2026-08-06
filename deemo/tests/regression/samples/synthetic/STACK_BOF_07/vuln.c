/* CWE-121: Stack overflow via recursive function with deep call chain */
#include <stdio.h>
#include <string.h>
void recurse(int depth, char *payload) {
    char buf[1024];
    strcpy(buf, payload);
    if (depth > 0) recurse(depth - 1, payload);
    printf("depth=%d\n", depth);
}
int main(int argc, char **argv) {
    recurse(argc>1?atoi(argv[1]):1000, argc>2?argv[2]:"A");
    return 0;
}
