#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
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

# Migrate older configurations without overwriting administrator choices.
ensure_config_default() {
  local key=$1 value=$2
  grep -q "^${key}=" /etc/t2-touchid.conf || printf '%s=%s\n' "$key" "$value" >>/etc/t2-touchid.conf
}
ensure_config_default T2_TOUCHID_MACOS_USER_ID 501
ensure_config_default T2_TOUCHID_SPECIAL_BAG -501
ensure_config_default T2_TOUCHID_ENROLLED_FINGER right-index-finger
ensure_config_default T2_TOUCHID_ENABLE_ACM_RESEARCH 0
ensure_config_default T2_TOUCHID_AKS_PLATFORM_ASID 0
ensure_config_default T2_TOUCHID_AKS_PLATFORM_CDHASH ''
chmod 0600 /etc/t2-touchid.conf

acm_research=$(sed -n 's/^T2_TOUCHID_ENABLE_ACM_RESEARCH=//p' /etc/t2-touchid.conf | tail -n 1)
if [[ $acm_research != 0 && $acm_research != 1 ]]; then
  echo "T2_TOUCHID_ENABLE_ACM_RESEARCH must be exactly 0 or 1." >&2
  exit 2
fi
mapfile -t macos_user_ids < <(
  sed -n 's/^T2_TOUCHID_MACOS_USER_ID=//p' /etc/t2-touchid.conf
)
if (( ${#macos_user_ids[@]} != 1 )); then
  echo "T2_TOUCHID_MACOS_USER_ID must occur exactly once." >&2
  exit 2
fi
macos_user_id=${macos_user_ids[0]}
if [[ ! $macos_user_id =~ ^[1-9][0-9]*$ || ${#macos_user_id} -gt 10 ]] || \
    (( 10#$macos_user_id < 10 || 10#$macos_user_id > 2147483647 )); then
  echo "T2_TOUCHID_MACOS_USER_ID cannot form a signed AKS alias." >&2
  exit 2
fi
mapfile -t special_bags < <(
  sed -n 's/^T2_TOUCHID_SPECIAL_BAG=//p' /etc/t2-touchid.conf
)
if (( ${#special_bags[@]} != 1 )) || \
    [[ ${special_bags[0]} != "-$macos_user_id" ]]; then
  echo "T2_TOUCHID_SPECIAL_BAG must be the derived negative Apple user ID." >&2
  exit 2
fi
aks_platform_cdhash=$(sed -n 's/^T2_TOUCHID_AKS_PLATFORM_CDHASH=//p' /etc/t2-touchid.conf | tail -n 1)
if [[ -n $aks_platform_cdhash && ! $aks_platform_cdhash =~ ^[[:xdigit:]]{40}$ ]]; then
  echo "T2_TOUCHID_AKS_PLATFORM_CDHASH must be empty or exactly 40 hexadecimal characters." >&2
  exit 2
fi
aks_platform_asid=$(sed -n 's/^T2_TOUCHID_AKS_PLATFORM_ASID=//p' /etc/t2-touchid.conf | tail -n 1)
if [[ ! $aks_platform_asid =~ ^[0-9]+$ ]] || (( aks_platform_asid > 4294967295 )); then
  echo "T2_TOUCHID_AKS_PLATFORM_ASID must be an unsigned 32-bit integer." >&2
  exit 2
fi

install -d -o root -g root -m 0755 "$target_dir" "$target_dir/src" /usr/local/lib/t2-touchid
install -d -o root -g root -m 0755 /usr/share/polkit-1/actions
install -d -o root -g root -m 0700 /var/lib/t2-touchid /var/lib/t2-touchid/users
install -o root -g root -m 0755 "$source_dir/src/"*.py "$target_dir/src/"
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-doctor.py" /usr/local/sbin/t2-touchid-doctor
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-inventory.py" /usr/local/sbin/t2-touchid-inventory
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-identities.py" /usr/local/sbin/t2-touchid-identities
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-manage.py" /usr/local/sbin/t2-touchid-manage
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-baseline.py" /usr/local/sbin/t2-touchid-baseline
install -o root -g root -m 0755 "$source_dir/src/t2-catacomb-fixture-check.py" /usr/local/sbin/t2-catacomb-fixture-check
install -o root -g root -m 0755 "$source_dir/src/t2-acm-preflight.py" /usr/local/sbin/t2-acm-preflight
install -o root -g root -m 0755 "$source_dir/src/t2-aks-observe-test.py" /usr/local/sbin/t2-aks-observe-test
install -o root -g root -m 0755 "$source_dir/src/t2-acm-lifecycle-test.py" /usr/local/sbin/t2-acm-lifecycle-test
install -o root -g root -m 0755 "$source_dir/src/t2-acm-policy-preflight.py" /usr/local/sbin/t2-acm-policy-preflight
install -o root -g root -m 0755 "$source_dir/src/t2-acm-authorize-test.py" /usr/local/sbin/t2-acm-authorize-test
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-enroll-test.py" /usr/local/sbin/t2-touchid-enroll-test
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-enroll.py" /usr/local/sbin/t2-touchid-enroll
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-user-map.py" /usr/local/sbin/t2-touchid-user-map
install -o root -g root -m 0644 "$source_dir/README.md" "$target_dir/README.md"
install -o root -g root -m 0644 "$source_dir/ROADMAP.md" "$target_dir/ROADMAP.md"
install -o root -g root -m 0644 \
  "$source_dir/polkit/org.t2linux.touchid.policy" \
  /usr/share/polkit-1/actions/org.t2linux.touchid.policy

python -m venv "$target_dir/.venv"
requirements_stamp=$target_dir/.requirements.sha256
requirements_hash=$(sha256sum "$source_dir/requirements.txt" | cut -d' ' -f1)
installed_hash=$(sed -n '1p' "$requirements_stamp" 2>/dev/null || true)
if [[ $installed_hash != "$requirements_hash" ]] || \
    ! "$target_dir/.venv/bin/python" -c 'import dbus_next, pymobiledevice3' 2>/dev/null; then
  "$target_dir/.venv/bin/pip" install --requirement "$source_dir/requirements.txt"
  printf '%s\n' "$requirements_hash" >"$requirements_stamp"
  chmod 0644 "$requirements_stamp"
else
  echo "Python dependencies are already installed."
fi

make -C "$source_dir/src"
install -o root -g root -m 0755 "$source_dir/src/t2-aks-tool" /usr/local/sbin/t2-aks-tool
install -o root -g root -m 0644 "$source_dir/src/t2_sep_transport.ko" /usr/local/lib/t2-touchid/t2_sep_transport.ko
install -o root -g root -m 0755 "$source_dir/src/t2-keybag-load.sh" /usr/local/sbin/t2-keybag-load
install -o root -g root -m 0700 "$source_dir/src/t2-pam-unlock.sh" /usr/local/sbin/t2-pam-unlock
install -o root -g root -m 0700 "$source_dir/src/t2-credential-unlock.sh" /usr/local/sbin/t2-credential-unlock
install -o root -g root -m 0700 "$source_dir/src/t2-biometric-ready.sh" /usr/local/sbin/t2-biometric-ready
install -o root -g root -m 0700 "$source_dir/src/t2-sep-transport-load.sh" /usr/local/sbin/t2-sep-transport-load
install -o root -g root -m 0644 "$source_dir/systemd/system/"*.service /etc/systemd/system/
install -d -o root -g root -m 0755 /etc/modprobe.d
module_options='options t2_sep_transport register_ool=1'
if [[ $acm_research == 1 ]]; then
  module_options+=" register_acm=1 aks_platform_asid=$aks_platform_asid aks_platform_proc_uniqueid=1"
  if [[ -n $aks_platform_cdhash ]]; then
    module_options+=" aks_platform_cdhash=${aks_platform_cdhash,,}"
  fi
fi
printf '%s\n' "$module_options" >/etc/modprobe.d/t2-sep-transport.conf
chmod 0644 /etc/modprobe.d/t2-sep-transport.conf

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
systemctl enable t2-sep-transport.service t2-keybag-load.service t2-credential-unlock.service t2-biometric-ready.service fprintd.service
systemctl reload dbus.service
systemctl --machine="$target_user@.host" --user daemon-reload || true

if command -v dkms >/dev/null 2>&1; then
  dkms_source=/usr/src/t2-sep-transport-0.1.0
  dkms_stamp=$dkms_source/.source.sha256
  module_source_hash=$(
    sha256sum "$source_dir/dkms.conf" "$source_dir/src/t2_sep_transport.c" \
      "$source_dir/src/t2_acm_lifecycle.h" \
      "$source_dir/src/t2_aks_protocol.h" \
      "$source_dir/src/t2_sep_transport_uapi.h" "$source_dir/src/Makefile" |
      awk '{print $1}' | sha256sum | awk '{print $1}'
  )
  installed_source_hash=$(sed -n '1p' "$dkms_stamp" 2>/dev/null || true)
  install -d -o root -g root -m 0755 "$dkms_source/src"
  install -o root -g root -m 0644 "$source_dir/dkms.conf" "$dkms_source/dkms.conf"
  install -o root -g root -m 0644 "$source_dir/src/t2_sep_transport.c" \
    "$source_dir/src/t2_acm_lifecycle.h" \
    "$source_dir/src/t2_aks_protocol.h" \
    "$source_dir/src/t2_sep_transport_uapi.h" "$source_dir/src/Makefile" "$dkms_source/src/"
  running_kernel=$(uname -r)
  dkms_state=$(dkms status -m t2-sep-transport -v 0.1.0 2>/dev/null || true)
  if grep -Fq "t2-sep-transport/0.1.0, $running_kernel" <<<"$dkms_state" && \
      grep -Fq ': installed' <<<"$dkms_state" && \
      [[ $installed_source_hash == "$module_source_hash" ]]; then
    echo "DKMS module is already installed for $running_kernel."
  else
    if [[ -z $dkms_state ]]; then
      dkms add -m t2-sep-transport -v 0.1.0
    fi
    dkms build --force -m t2-sep-transport -v 0.1.0 -k "$running_kernel"
    dkms install --force -m t2-sep-transport -v 0.1.0 -k "$running_kernel"
    printf '%s\n' "$module_source_hash" >"$dkms_stamp"
    chmod 0644 "$dkms_stamp"
  fi
else
  echo "Warning: dkms is unavailable; rerun this installer after kernel upgrades." >&2
fi

echo "Core files installed. Follow README.md to provision the private keybag,"
echo "start the transport and keybag services, unlock the bags, and run controls."
echo "Do not install the PAM templates until both controls pass."
