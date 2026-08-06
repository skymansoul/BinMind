/* CVE-2018-16864 CWE-121: 栈缓冲区溢出: gets读取无界数据 */
#include <stdio.h>
void vuln(){char buf[64];gets(buf);}
int main(){vuln();return 0;}
