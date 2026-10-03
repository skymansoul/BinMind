#include <stdio.h>
#include <string.h>
void parse_grub_cfg(char*cfg){char line[256];strcpy(line,cfg);printf("%s",line);}
int main(int c,char**v){parse_grub_cfg(v[1]?v[1]:"default=0");return 0;}