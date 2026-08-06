/* GENERIC-fmt-logging CWE-134: 日志函数格式串可控 */
#include <stdio.h>
#include <stdlib.h>
void log_it(char* fmt, char* arg) { char b[256]; snprintf(b, sizeof(b), fmt, arg); puts(b); }
int main(int c, char** v) { log_it(c>1?v[1]:"%s", c>2?v[2]:"ok"); return 0; }