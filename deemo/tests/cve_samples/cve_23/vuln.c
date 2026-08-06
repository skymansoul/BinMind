/* Stack buffer overflow via sprintf / CWE-121 */
#include <stdio.h>
#include <string.h>
void format_name(char *first, char *last) {
    char buf[64];
    sprintf(buf, "%s %s", first, last); /* BUG: total may exceed 64 */
}
int main(void) { format_name("AAAA...40chars", "BBBB...40chars"); return 0; }
