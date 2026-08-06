#include <stdio.h>
#include <string.h>
void parse_http_header(char*val){char hdr[256];strcpy(hdr,val);printf("%s",hdr);}
int main(int c,char**v){parse_http_header(v[1]?v[1]:"Host: localhost");return 0;}