#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail
PATH=/usr/bin:/bin
export PATH

if [[ $EUID -ne 0 ]]; then
  echo 'Run with sudo: sudo tools/provision-credential.sh' >&2
  exit 1
fi

credential_dir=/etc/credstore.encrypted
credential_file=$credential_dir/t2-touchid-password
if [[ -e $credential_file ]]; then
  echo "$credential_file already exists; remove it explicitly before reprovisioning." >&2
  exit 1
fi

install -d -o root -g root -m 0700 "$credential_dir"
systemd-ask-password 'macOS/Linux password for unattended T2 keybag unlock:' |
  systemd-creds encrypt --with-key=host --name=t2-touchid-password \
    - "$credential_file"
chmod 0600 "$credential_file"
echo 'Encrypted T2 credential provisioned. Reboot to test unattended unlock.'
