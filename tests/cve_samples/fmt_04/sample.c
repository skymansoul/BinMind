#include <stdio.h>
#include <string.h>
void ftp_log(char*cmd){fprintf(stderr,cmd);}
int main(int c,char**v){if(c>1)ftp_log(v[1]);return 0;}