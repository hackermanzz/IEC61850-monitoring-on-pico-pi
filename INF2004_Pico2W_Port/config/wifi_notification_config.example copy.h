/* Copy to wifi_notification_config.h in this directory; that file is ignored.
 * Never paste credentials into build commands, logs or source control.
 */
#ifndef WIFI_NOTIFICATION_CONFIG_H
#define WIFI_NOTIFICATION_CONFIG_H
#define WIFI_SSID     ""
#define WIFI_PASSWORD ""
#define TELEBOT_TOKEN ""
#define CHATID        ""
/* A PEM trusted root encoded as adjacent C string literals.
 * Verify the root through your trusted certificate source. Never a leaf pin.
 */
#define CA_ROOT_CERT   ""
/* Optional trusted Unix UTC at boot; zero requires the USB utc command.
 * A fixed value becomes stale: update before boot or set UTC over USB.
 */
#define MONITOR_UTC_AT_BOOT 0
#endif

/*** end of file ***/
