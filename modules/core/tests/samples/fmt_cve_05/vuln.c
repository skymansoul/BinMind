#include <stdio.h>
#include <wchar.h>
void vuln(wchar_t *f) { wprintf(f); }
int main(){wprintf(L"%hn %hn");}