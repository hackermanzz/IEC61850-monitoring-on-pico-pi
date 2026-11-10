/** @file wifi_settings.h
 * @brief Configuration boundary keeps offline builds representative without
 * LTO.
 */
#ifndef PORT_WIFI_SETTINGS_H
#define PORT_WIFI_SETTINGS_H
#include <stddef.h>
#include <stdint.h>
extern const char     g_wifi_ntp_server[];
extern const char     g_wifi_ntp_fallback[];
extern const char     g_wifi_ssid[];
extern const char     g_wifi_password[];
extern const char     g_telegram_token[];
extern const char     g_telegram_chat[];
extern const char     g_wifi_ca_root[];
extern const size_t   g_wifi_ca_root_size;
extern const uint32_t g_wifi_boot_utc;
#ifndef PORT_WIFI_SETTINGS_IMPLEMENTATION
#define WIFI_SSID     g_wifi_ssid
#define WIFI_PASSWORD g_wifi_password
#define TELEBOT_TOKEN g_telegram_token
#define CHATID        g_telegram_chat
#define CA_ROOT_CERT  g_wifi_ca_root
#endif
#endif

/*** end of file ***/
