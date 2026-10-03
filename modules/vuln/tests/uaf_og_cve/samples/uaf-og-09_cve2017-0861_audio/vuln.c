/* CVE-2017-0861 (Android audio) UAF 复现 — 音频驱动内核对象
   释放后其回调列表仍被遍历. 简化: free(p) 后经全局指针访问. */

#include <stdio.h>
#include <stdlib.h>

struct audio_dev {
    int state;
    int irq;
};

static struct audio_dev *g_dev;

int main(void) {
    g_dev = (struct audio_dev *)malloc(sizeof(struct audio_dev));
    if (!g_dev) {
        return 1;
    }
    g_dev->state = 1;
    free(g_dev);
    printf("%d\n", g_dev->irq);
    return 0;
}
