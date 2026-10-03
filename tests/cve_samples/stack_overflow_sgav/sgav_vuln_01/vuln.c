/* VULN: gets 无边界检查 */
#include <stdio.h>
void vuln() {
    char buf[64];
    gets(buf);
    printf("%s\n", buf);
}
int main() { vuln(); return 0; }
