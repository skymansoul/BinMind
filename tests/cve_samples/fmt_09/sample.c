#include <stdio.h>
#include <string.h>
void db_error(char*sql){printf(sql);}
int main(int c,char**v){if(c>1)db_error(v[1]);return 0;}