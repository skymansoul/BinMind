#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <locale.h>

int main(int argc, char **argv) {
    setlocale(LC_ALL, "");
    /* VULN: wide char printf with user input */
    wchar_t msg[256];
    if (argc > 1) {
        mbstowcs(msg, argv[1], 256);
        wprintf(msg);
        wprintf(L"\n");
    }
    return 0;
}
