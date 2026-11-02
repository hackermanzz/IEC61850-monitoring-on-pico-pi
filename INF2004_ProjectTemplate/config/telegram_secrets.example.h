/* Copy to telegram_secrets.h. Never commit credentials. */
#define TELEBOT_TOKEN ""
#define CHATID ""
#define CA_ROOT_CERT "" /* PEM root CA, including BEGIN/END CERTIFICATE */
/* For a multiline certificate, every line except the last needs a trailing
 * backslash, and each certificate line is a quoted C string ending in \n:
 * #define CA_ROOT_CERT \
 * "-----BEGIN CERTIFICATE-----\n" \
 * "BASE64_CERTIFICATE_DATA\n" \
 * "-----END CERTIFICATE-----\n"
 */
/* Trusted UTC Unix seconds at boot, or provide it later to the service owner.
 * Zero disables HTTPS submission until trusted UTC is supplied. */
#define MONITOR_UTC_AT_BOOT 0
