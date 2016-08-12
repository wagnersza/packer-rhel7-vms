#!/usr/bin/env bash
set -x

echo "Modifying /etc/ssh/sshd_config..."

sed -i -e 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config

cat >> /etc/ssh/sshd_config <<EOL
UseDNS no
GSSAPIAuthentication no
Protocol 2
LogLevel INFO
MaxAuthTries 4
IgnoreRhosts yes
HostbasedAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
PermitUserEnvironment no
Ciphers aes128-ctr,aes192-ctr,aes256-ctr
ClientAliveInterval 300
ClientAliveCountMax 0
Banner /etc/issue.net
HostbasedAuthentication no
EOL