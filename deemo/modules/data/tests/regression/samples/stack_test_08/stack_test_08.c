#include <stdio.h>
void vuln() { char buf[12]; fgets(buf,256,stdin); }
int main() { vuln(); return 0; }