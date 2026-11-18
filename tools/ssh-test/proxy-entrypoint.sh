#!/bin/sh
# The SOCKS5 proxies, the SOCKS4/4A one and the HTTP proxy with a password in
# the background, the open HTTP proxy in the foreground.
set -e
microsocks -i 0.0.0.0 -p 1080 &
microsocks -i 0.0.0.0 -p 1081 -u proxyuser -P proxypass &
tinyproxy -d -c /etc/tinyproxy/tinyproxy-auth.conf &

# SOCKS4 and SOCKS4A come from OpenSSH's dynamic forwarding into the test
# server: the server opens the connection, so 127.0.0.1:22 and ssh:22 both
# reach its sshd. The bind mount comes with Windows permissions, which ssh
# refuses for a private key, so the key is copied with the mode it expects.
install -m 600 /keys/id_ed25519 /tmp/id_ed25519
(
    while true; do
        ssh -N -g -D 0.0.0.0:1082 -i /tmp/id_ed25519 \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
            -o LogLevel=ERROR tester@ssh || true
        sleep 1
    done
) &

exec tinyproxy -d -c /etc/tinyproxy/tinyproxy.conf
