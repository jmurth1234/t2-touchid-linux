#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo ./install.sh" >&2
  exit 1
fi
if [[ -z ${SUDO_USER:-} || $SUDO_USER == root ]]; then
  echo "Run through sudo from the desktop user that will use Touch ID." >&2
  exit 1
fi

source_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
target_dir=/opt/t2-touchid
target_user=$SUDO_USER
target_home=$(getent passwd "$target_user" | cut -d: -f6)
if [[ -z $target_home || ! -d $target_home ]]; then
  echo "Could not determine the home directory for $target_user." >&2
  exit 1
fi

if [[ ! -f /etc/t2-touchid.conf ]]; then
  install -o root -g root -m 0600 "$source_dir/t2-touchid.conf.example" /etc/t2-touchid.conf
  sed -i "s/^T2_TOUCHID_USER=.*/T2_TOUCHID_USER=$target_user/" /etc/t2-touchid.conf
  echo "Edit /etc/t2-touchid.conf with this machine's T2 host and interface, then rerun." >&2
  exit 2
fi

install -d -o root -g root -m 0755 "$target_dir" "$target_dir/src" /usr/local/lib/t2-touchid
install -o root -g root -m 0755 "$source_dir/src/"*.py "$target_dir/src/"
install -o root -g root -m 0644 "$source_dir/README.md" "$target_dir/README.md"

python -m venv "$target_dir/.venv"
"$target_dir/.venv/bin/pip" install --requirement "$source_dir/requirements.txt"

make -C "$source_dir/src"
install -o root -g root -m 0755 "$source_dir/src/t2-aks-tool" /usr/local/sbin/t2-aks-tool
install -o root -g root -m 0644 "$source_dir/src/t2_sep_transport.ko" /usr/local/lib/t2-touchid/t2_sep_transport.ko
install -o root -g root -m 0755 "$source_dir/src/t2-keybag-load.sh" /usr/local/sbin/t2-keybag-load
install -o root -g root -m 0644 "$source_dir/systemd/system/"*.service /etc/systemd/system/

install -d -o "$target_user" -g "$target_user" -m 0755 "$target_home/.config/systemd/user"
install -o "$target_user" -g "$target_user" -m 0644 \
  "$source_dir/systemd/user/"*.service "$target_home/.config/systemd/user/"

cat >/etc/dbus-1/system.d/99-t2-touchid-fprint.conf <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy context="default"><deny send_destination="net.reactivated.Fprint"/></policy>
  <policy user="root"><allow own="net.reactivated.Fprint"/><allow send_destination="net.reactivated.Fprint"/></policy>
  <policy user="$target_user"><allow send_destination="net.reactivated.Fprint"/></policy>
</busconfig>
EOF
chmod 0644 /etc/dbus-1/system.d/99-t2-touchid-fprint.conf

systemctl daemon-reload
systemctl enable t2-sep-transport.service t2-keybag-load.service fprintd.service
systemctl reload dbus.service
sudo -u "$target_user" systemctl --user daemon-reload || true

echo "Core files installed. Follow README.md to provision the private keybag,"
echo "start the transport and keybag services, unlock the bags, and run controls."
echo "Do not install the PAM templates until both controls pass."
