#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

PATH=/usr/bin:/bin
export PATH

config_file=/etc/t2-touchid.conf
port_file=/var/lib/t2-touchid/biometric-port

read_config() {
  sed -n "s/^$1=//p" "$config_file" | tail -n 1
}

host=$(read_config T2_TOUCHID_HOST)
interface=$(read_config T2_TOUCHID_INTERFACE)
project=$(read_config T2_TOUCHID_PROJECT_DIR)
[[ -n $host && -n $interface && -n $project ]] || {
  echo "T2 BridgeXPC discovery configuration is incomplete" >&2
  exit 1
}

if [[ -x $project/.venv/bin/python && -f $project/src/discover-biometric-port.py ]]; then
  python=$project/.venv/bin/python
  discovery=$project/src/discover-biometric-port.py
elif [[ -x $project/.venv-re/bin/python && -f $project/linux/discover-biometric-port.py ]]; then
  python=$project/.venv-re/bin/python
  discovery=$project/linux/discover-biometric-port.py
  export PYTHONPATH=$project/third-party/pymobiledevice3
else
  echo "T2 BridgeXPC discovery helper is unavailable" >&2
  exit 1
fi

# The RemoteXPC query identifies the advertised BiometricKit service instead
# of trusting whichever dynamic TCP port happens to be open on BridgeOS.
deadline=$((SECONDS + 45))
port=
while (( SECONDS < deadline )); do
  if port=$(
    "$python" "$discovery" \
      --host "$host" --interface "$interface" \
      --probe-timeout 0.2 --concurrency 256 2>/dev/null
  ); then
    break
  fi
  port=
  sleep 1
done
[[ $port =~ ^[0-9]+$ && $port -ge 49152 && $port -le 65535 ]] || {
  echo "T2 did not advertise a valid BiometricKit port" >&2
  exit 1
}

install -d -o root -g root -m 0700 "${port_file%/*}"
temporary_port_file=$(mktemp "${port_file}.XXXXXX")
trap 'rm -f "$temporary_port_file"' EXIT
printf '%s\n' "$port" >"$temporary_port_file"
chmod 0600 "$temporary_port_file"
mv -f "$temporary_port_file" "$port_file"
trap - EXIT

logger --priority authpriv.info --tag t2-biometric-port-refresh \
  "refreshed the dynamic T2 BiometricKit port"
