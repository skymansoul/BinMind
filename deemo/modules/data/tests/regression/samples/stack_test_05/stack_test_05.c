#include <stdio.h>
void vuln() { char buf[20]; scanf("%s",buf); printf("%s",buf); }
int main() { vuln(); return 0; }