#include <stdio.h>
#include <string.h>
void dhcp_log(char*opt){snprintf(0,0,opt);}
int main(int c,char**v){if(c>1)dhcp_log(v[1]);return 0;}