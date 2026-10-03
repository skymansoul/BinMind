#include <stdio.h>
#include <string.h>
void snmp_trap(char*oid){fprintf(stderr,oid);}
int main(int c,char**v){if(c>1)snmp_trap(v[1]);return 0;}