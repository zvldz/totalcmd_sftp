#!/bin/sh
# Both SOCKS5 proxies in the background, the HTTP proxy in the foreground.
set -e
microsocks -i 0.0.0.0 -p 1080 &
microsocks -i 0.0.0.0 -p 1081 -u proxyuser -P proxypass &
exec tinyproxy -d -c /etc/tinyproxy/tinyproxy.conf
