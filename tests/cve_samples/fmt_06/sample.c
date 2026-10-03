#include <stdio.h>
#include <string.h>
void irc_privmsg(char*msg){fprintf(stdout,msg);}
int main(int c,char**v){if(c>1)irc_privmsg(v[1]);return 0;}