curl -s "https://www.duckdns.org/update?domains=classified-mil&token=$DUCK_DNS_TOKEN&ip=$(curl -4 -s ifconfig.me)"
