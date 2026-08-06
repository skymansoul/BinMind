/* Format string sample 10 — printf with user-controlled format / CWE-134 */
#include <stdio.h>
void log_msg(const char *user_input) { printf(user_input); } /* BUG */
int main(int argc, char **argv) {
    if (argc > 1) log_msg(argv[1]); return 0;
}
