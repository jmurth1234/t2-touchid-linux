#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

usage() {
  echo "Usage: sudo $0 OUTPUT_DIRECTORY [--freeze-daemon]" >&2
  exit 2
}

[[ $(uname -s) == Darwin ]] || { echo "This collector must run on macOS." >&2; exit 1; }
[[ $# -ge 1 && $# -le 2 ]] || usage

output=$1
freeze=0
[[ ${2:-} == --freeze-daemon ]] && freeze=1
[[ ${2:-} == "" || ${2:-} == --freeze-daemon ]] || usage
[[ ! -e $output ]] || { echo "Refusing to overwrite: $output" >&2; exit 1; }

daemon_pid=""
cleanup() {
  if [[ -n $daemon_pid ]]; then
    kill -CONT "$daemon_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT HUP INT TERM

umask 077
mkdir -p "$output/files"
chmod 700 "$output" "$output/files"

if (( freeze )); then
  daemon_pid=$(pgrep -x biometrickitd | head -n 1 || true)
  [[ -n $daemon_pid ]] || { echo "biometrickitd is not running." >&2; exit 1; }
  kill -STOP "$daemon_pid"
fi

root=/Library/Catacomb
[[ -d $root ]] || { echo "$root does not exist." >&2; exit 1; }

ditto --noqtn "$root" "$output/files/Library-Catacomb"

{
  sw_vers 2>/dev/null || true
  printf 'captured_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'freeze_daemon=%s\n' "$freeze"
  stat -f 'source_mode=%Sp source_owner=%Su:%Sg' "$root"
} > "$output/metadata.txt"

find "$output/files" -type f -print0 \
  | sort -z \
  | xargs -0 shasum -a 256 > "$output/manifest.sha256"

chmod -R go-rwx "$output"
echo "Private fixtures written to: $output"
echo "Do not commit or publish this directory."
