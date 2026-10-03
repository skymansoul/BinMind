/* CVE-2013-4786 — IPMI firmware format string vulnerability
   Type: format_string
   gcc -O0 ipmi_fmt.c -o ipmi_fmt

   BMC firmware passed attacker-controlled sensor data
   directly to syslog as format string. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void log_sensor_data(const char *sensor_name, const char *sensor_value) {
    char log_buf[512];
    /* BUG: sensor_value is attacker-controlled via IPMI request,
       passed to syslog as format string */
    snprintf(log_buf, sizeof(log_buf), sensor_value, sensor_name);
    printf("[SENSOR] ");
    printf(log_buf);  /* format string vulnerability */
    printf("\n");
}

int main(int argc, char **argv) {
    const char *val = (argc > 1) ? argv[1] : "%s%s%s%n";
    log_sensor_data("CPU_TEMP", val);
    return 0;
}
