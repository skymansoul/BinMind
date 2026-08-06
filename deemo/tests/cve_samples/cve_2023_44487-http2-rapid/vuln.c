/* CVE-2023-44487: HTTP/2 Rapid Reset 堆溢出 —— 简化: 流累积溢出 */
#include <stdlib.h>
#include <string.h>
void http2_accumulate_streams(char **streams, int nstreams) {
    size_t total = 0;
    for(int i=0;i<nstreams;i++) total += strlen(streams[i]);
    char *buf = malloc(total);
    /* BUG: total 可能极大(多流累积), 未做上限检查 */
    for(int i=0;i<nstreams;i++) strcat(buf, streams[i]);
    free(buf);
}
int main() { char *s[]={"A","B"}; http2_accumulate_streams(s,2); return 0; }
