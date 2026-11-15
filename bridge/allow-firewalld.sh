#!/bin/sh
# Opens 11436/tcp in firewalld ONLY for the firewall address(es), permanently.
# Usage: FIREWALL_IPS="192.168.1.1 192.168.1.2" ./allow-firewalld.sh
# To revert, run the same commands with --remove-rich-rule.
set -e
: "${FIREWALL_IPS:?set FIREWALL_IPS to the LAN address(es) of the firewall}"
for ip in $FIREWALL_IPS; do
  sudo firewall-cmd --permanent --zone=public --add-rich-rule="rule family=ipv4 source address=$ip/32 port port=11436 protocol=tcp accept"
done
sudo firewall-cmd --reload
sudo firewall-cmd --zone=public --list-rich-rules
