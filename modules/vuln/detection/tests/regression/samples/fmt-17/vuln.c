/* FMT-17: 字符串拼接后作为格式字符串 */
#include <stdio.h>
#include <string.h>
int main(int c,char**v) { char b[128]; strcpy(b,"["); strcat(b,v[1]); strcat(b,"]"); printf(b); return 0; }
