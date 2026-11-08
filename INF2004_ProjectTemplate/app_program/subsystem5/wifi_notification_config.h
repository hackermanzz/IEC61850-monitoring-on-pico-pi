#ifndef MONITOR_WIFI_NOTIFICATION_CONFIG_H
#define MONITOR_WIFI_NOTIFICATION_CONFIG_H
/* Optional local secrets. Without this file no request is submitted. */
#if MONITOR_TLS_COMPILE_TEST
/* Compile reachability only: invalid CA, fake IDs, UTC remains unavailable.
 * This profile cannot submit a request and is never a delivery test. */
#define TELEBOT_TOKEN "compile-test-token"
#define CHATID "compile-test-chat"
#define CA_ROOT_CERT "-----BEGIN CERTIFICATE-----\ncompile reachability fixture, deliberately invalid, not a trust root\n-----END CERTIFICATE-----\n"
#elif __has_include("telegram_secrets.h")
#include "telegram_secrets.h"
#else
#define TELEBOT_TOKEN ""
#define CHATID ""
#define CA_ROOT_CERT ""
#endif
#endif
