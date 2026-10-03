/* stack-overflow-05: gets()无边界检查
 * 类型: stack buffer overflow
 */
#include <stdio.h>
void vuln() { char buf[32]; gets(buf); puts(buf); }
int main() { vuln(); return 0; }
