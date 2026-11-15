# OpenSSH server for the plugin's integration tests.
# openssh-client brings the scp binary the server side of SCP mode runs.
FROM debian:stable-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server openssh-client \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/bash tester \
 && echo 'tester:tester' | chpasswd

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
