/* UAF-003: 条件分支中的free→use */
#include <stdio.h>
#include <stdlib.h>
void process(char *data, int free_first) {
    if (free_first) { free(data); }
    printf("%s\n", data); /* UAF if free_first=1 */
}
int main() {
    char *buf = malloc(128);
    strcpy(buf, "test");
    process(buf, 1);
    return 0;
}
