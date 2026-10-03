#include <stdio.h>
void vuln() { char buf[16]; gets(buf); printf("%s",buf); }
int main() { vuln(); return 0; }