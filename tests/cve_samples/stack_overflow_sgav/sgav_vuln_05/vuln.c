/* VULN: scanf("%s") 无宽度限定 */
#include <stdio.h>
void vuln() {
    char buf[64];
    scanf("%s", buf);
}
int main() { vuln(); return 0; }
