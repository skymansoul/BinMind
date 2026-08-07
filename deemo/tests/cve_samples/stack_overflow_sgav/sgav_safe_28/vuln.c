/* SAFE: scanf("%31s") 有宽度限定 */
#include <stdio.h>
void safe_input() {
    char buf[32];
    scanf("%31s", buf);
}
int main() { safe_input(); return 0; }
