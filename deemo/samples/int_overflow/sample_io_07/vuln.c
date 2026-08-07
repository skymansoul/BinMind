/* CVE-2016-10190 FFmpeg: integer overflow in av_malloc_array(nmemb, size)
 * nmemb=0x40000000, size=8 → nmemb*size = 0 in 32-bit → allocation too small.
 * EXPECT: TP (CVE-confirmed pattern)
 */
#include <stdlib.h>
#include <string.h>
static void *av_malloc_array(size_t nmemb, size_t size) {
    if (nmemb > 0x7FFFFFFF || size > 0x7FFFFFFF) return NULL;
    return malloc(nmemb * size); /* overflow here */
}
void process_frames(int num_frames, char *frame_data, size_t frame_sz) {
    char **frames = (char**)av_malloc_array(num_frames, sizeof(char*));
    if (!frames) return;
    for (int i = 0; i < num_frames; i++) {
        frames[i] = (char*)malloc(frame_sz);
        memcpy(frames[i], frame_data + i * frame_sz, frame_sz);
    }
    for (int i = 0; i < num_frames; i++) free(frames[i]);
    free(frames);
}
