#!/bin/sh
# "gen-keys" writes the test keys into /keys and exits; otherwise the test
# account is given /keys/authorized_keys and sshd runs in the foreground.
set -e

if [ "$1" = "gen-keys" ]; then
    rm -f /keys/id_ed25519 /keys/id_ed25519.pub
    ssh-keygen -q -t ed25519 -N '' -C plugin-test -f /keys/id_ed25519
    cp /keys/id_ed25519.pub /keys/authorized_keys
    echo "keys written to /keys"
    exit 0
fi

# Stands in for OpenWrt / Dropbear: an sftp-server binary but no subsystem.
if [ "$NO_SFTP_SUBSYSTEM" = "1" ]; then
    sed -i '/^Subsystem[[:space:]]/d' /etc/ssh/sshd_config
fi

# The bind mount comes with Windows permissions, which sshd's StrictModes
# refuses, so the keys are copied with the modes it expects.
install -d -m 700 -o tester -g tester /home/tester/.ssh
if [ -f /keys/authorized_keys ]; then
    install -m 600 -o tester -g tester /keys/authorized_keys /home/tester/.ssh/authorized_keys
fi

exec /usr/sbin/sshd -D -e
