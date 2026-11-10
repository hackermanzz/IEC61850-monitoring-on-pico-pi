/** @file wifi_settings.c
 * @brief Only this translation unit reads private credentials.
 */
#define PORT_WIFI_SETTINGS_IMPLEMENTATION
#include "wifi_settings.h"
#include <stddef.h>
#include <stdint.h>
#if __has_include("wifi_notification_config.h")
#include "wifi_notification_config.h"
#else
#include "wifi_notification_config.example.h"
#endif
#ifndef MONITOR_UTC_AT_BOOT
#define MONITOR_UTC_AT_BOOT 0
#endif
#ifndef WIFI_NTP_SERVER
#define WIFI_NTP_SERVER "time.cloudflare.com"
#endif
#ifndef WIFI_NTP_FALLBACK
#define WIFI_NTP_FALLBACK "time.google.com"
#endif
const char     g_wifi_ntp_server[]   = WIFI_NTP_SERVER;
const char     g_wifi_ntp_fallback[] = WIFI_NTP_FALLBACK;
const char     g_wifi_ssid[]         = WIFI_SSID;
const char     g_wifi_password[]     = WIFI_PASSWORD;
const char     g_telegram_token[]    = TELEBOT_TOKEN;
const char     g_telegram_chat[]     = CHATID;
const char     g_wifi_ca_root[]      = CA_ROOT_CERT;
const size_t   g_wifi_ca_root_size   = sizeof(g_wifi_ca_root);
const uint32_t g_wifi_boot_utc       = MONITOR_UTC_AT_BOOT;

/*** end of file ***/
