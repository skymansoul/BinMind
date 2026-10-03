/* FP-TEST-05: loop bound constrained by allocation size.
 * malloc(N), for(i=0; i<N && i<alloc_sz; i++) buf[i] = x.
 * The loop bound i<N where N=alloc_sz ensures write within bounds.
 * Loop guard analysis should prove SAFE and FILTER.
 */
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 128

void init_buffer(void) {
    char *buf = (char *)malloc(BUF_SIZE);
    if (buf == NULL) return;
    /* loop bound i < BUF_SIZE ensures safety */
    for (int i = 0; i < BUF_SIZE; i++) {
        buf[i] = (char)i;
    }
    free(buf);
}

int main(void) {
    init_buffer();
    return 0;
}
