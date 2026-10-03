/* CWE-681: Signed→unsigned confusion in allocation size
 * len is signed int, passed directly to malloc as size_t.
 * len=-1 → malloc(SIZE_MAX) → OOM or small alloc + overflow.
 * EXPECT: TP
 */
#include <stdlib.h>
#include <string.h>
void process_data(int len, char *data) {
    if (len > 4096) return;        /* signed check, -1 passes */
    char *buf = (char*)malloc(len); /* len=-1 → huge unsigned alloc */
    if (!buf) return;
    memcpy(buf, data, len);        /* len=-1 → huge copy */
    free(buf);
}
