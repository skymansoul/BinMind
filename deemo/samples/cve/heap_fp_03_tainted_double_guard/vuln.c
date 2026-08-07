/* heap_fp_03: user-controlled alloc but double-guarded write
 * Taint says KEEP (user input); VFS+Guard say SUPPRESS → ensemble REVIEW.
 * Real-world pattern: safe wrappers that validate before writing.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
void handle_request(int user_len, char *data) {
    if (user_len <= 0 || user_len > 4096) return;
    char *buf = (char*)malloc(user_len);  /* tainted alloc */
    if (!buf) return;
    if ((size_t)user_len <= strlen(data)) return;  /* guard 1 */
    if (user_len > 4000) return;                    /* guard 2 */
    memcpy(buf, data, user_len - 1);  /* guarded, but user-controlled size */
    free(buf);
}
