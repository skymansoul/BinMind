/* CWE-416: UAF via function pointer table after free.
   Common pattern in C++ vtables and C callback tables. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef void (*handler_t)(const char *);
typedef struct { handler_t on_data; handler_t on_error; } Callbacks;
static void log_data(const char *s) { printf("DATA: %s\n", s); }
static void log_err(const char *s)  { printf("ERR: %s\n", s); }
int main(void) {
    Callbacks *cb = malloc(sizeof(Callbacks));
    cb->on_data = log_data; cb->on_error = log_err;
    cb->on_data("before free");
    free(cb);
    cb->on_data("after free"); /* UAF: cb->on_data is dangling function ptr */
    return 0;
}
