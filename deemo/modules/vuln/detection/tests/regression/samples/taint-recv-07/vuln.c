/* taint-recv-07: 输入直达system()——命令注入
 * Ground Truth: 污点数据直达system
 */
#include <stdlib.h>
#include <unistd.h>
void handle_cmd() {
    char cmd[256]; read(0, cmd, 255);
    system(cmd);  /* BUG: 污点数据直达system */
}
int main() { handle_cmd(); return 0; }
