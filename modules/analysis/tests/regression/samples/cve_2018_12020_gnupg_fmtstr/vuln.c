#include <stdio.h>
#include <string.h>
void print_status(const char *fn, int st) {
    char line[512];
    snprintf(line, sizeof(line), fn, st); /* BUG: filename as format */
    printf("%s", line);
}
int main(int a, char **v) { if(a<2) return 1;
    print_status(v[1], 0); return 0; }