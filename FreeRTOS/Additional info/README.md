Edit wifi_notification.h

- wifi name, password
- telegram bot
- chatid with telegram bot

`cmake -S . -B build`

`cmake --build build`

obtain certificate:
```
openssl s_client -connect ntfy.sh:443 -showcerts </dev/null
```
telebot: PassiveIEC61850MonitorNotifbot

https://api.telegram.org/bot[token]/getUpdates

curl -X POST "https://api.telegram.org/bot[token]/sendMessage" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "chat_id=[chatid]&text=test"