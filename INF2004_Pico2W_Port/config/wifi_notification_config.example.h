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
#define CA_ROOT_CERT ""
/* Optional Unix UTC at boot; leave zero for automatic network time.
 * A nonzero fixed value becomes stale and overrides network time.
 */
#define MONITOR_UTC_AT_BOOT 0
/* Optional overrides: use your local time server if public NTP is blocked. */
#define WIFI_NTP_SERVER   "time.cloudflare.com"
#define WIFI_NTP_FALLBACK "time.google.com"
#endif

/*** end of file ***/
