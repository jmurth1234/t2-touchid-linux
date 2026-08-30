#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

usage() {
  cat >&2 <<EOF
Usage: $0 [OUTPUT_FILE]

Collects the audit-session ID and process-unique ID of the currently running
macOS processes that may call AppleKeyStore selector 42. The default output is
/Volumes/OMARCHY_EFI/t2-aks-platform-identities.tsv.

The output is private, boot-scoped research evidence. Do not publish it.
EOF
  exit 2
}

[[ $(uname -s) == Darwin ]] || {
  echo "This collector must run on macOS." >&2
  exit 1
}
[[ $# -le 1 ]] || usage
[[ $EUID -ne 0 ]] || {
  echo "Run this as your normal macOS user; it invokes sudo for process metadata." >&2
  exit 1
}

output=${1:-/Volumes/OMARCHY_EFI/t2-aks-platform-identities.tsv}
case $output in
  /*) ;;
  *) output="$PWD/$output" ;;
esac
[[ ! -e $output ]] || {
  echo "Refusing to overwrite existing output: $output" >&2
  exit 1
}
parent=$(dirname "$output")
[[ -d $parent && -w $parent ]] || {
  echo "Output parent is not writable: $parent" >&2
  echo "Mount OMARCHY_EFI in Finder, or pass another destination." >&2
  exit 1
}

work=$(mktemp -d /tmp/t2-aks-platform.XXXXXX)
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM
umask 077

# The two private proc_pidinfo declarations are copied locally so this helper
# builds against a normal macOS SDK. Their layout and flavor are published in
# Apple's XNU proc_info.h; auditpinfo_addr and A_GETPINFO_ADDR are public BSM.
cat >"$work/collect.c" <<'EOF'
#include <bsm/audit.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define PROC_PIDUNIQIDENTIFIERINFO 17

struct proc_uniqidentifierinfo_local {
    uint8_t p_uuid[16];
    uint64_t p_uniqueid;
    uint64_t p_puniqueid;
    int32_t p_idversion;
    uint32_t p_reserve2;
    uint64_t p_reserve3;
    uint64_t p_reserve4;
};

extern int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer,
                        int buffersize);

int main(int argc, char **argv)
{
    int failures = 0;

    if (argc < 2) {
        fprintf(stderr, "no process IDs supplied\n");
        return 2;
    }
    puts("pid\taudit_session_id\tprocess_unique_id\tparent_process_unique_id\tpid_version");
    for (int i = 1; i < argc; i++) {
        struct proc_uniqidentifierinfo_local unique = { 0 };
        struct auditpinfo_addr audit = { 0 };
        char *end = NULL;
        long parsed;
        int got;

        errno = 0;
        parsed = strtol(argv[i], &end, 10);
        if (errno || !end || *end || parsed <= 0 || parsed > INT_MAX) {
            fprintf(stderr, "invalid process ID: %s\n", argv[i]);
            failures++;
            continue;
        }
        audit.ap_pid = (pid_t)parsed;
        if (auditon(A_GETPINFO_ADDR, &audit, (int)sizeof(audit)) != 0) {
            fprintf(stderr, "auditon pid %ld: %s\n", parsed,
                    strerror(errno));
            failures++;
            continue;
        }
        got = proc_pidinfo((int)parsed, PROC_PIDUNIQIDENTIFIERINFO, 0,
                           &unique, (int)sizeof(unique));
        if (got != (int)sizeof(unique)) {
            if (got >= 0)
                fprintf(stderr, "proc_pidinfo pid %ld: short result %d\n",
                        parsed, got);
            else
                fprintf(stderr, "proc_pidinfo pid %ld: %s\n", parsed,
                        strerror(errno));
            failures++;
            continue;
        }
        printf("%ld\t%d\t%llu\t%llu\t%d\n", parsed, audit.ap_asid,
               (unsigned long long)unique.p_uniqueid,
               (unsigned long long)unique.p_puniqueid,
               unique.p_idversion);
    }
    return failures ? 1 : 0;
}
EOF

xcrun clang -std=c11 -O2 -Wall -Wextra -Werror \
  -Wno-deprecated-declarations "$work/collect.c" -o "$work/collect"

processes="$work/processes.tsv"
{
  printf 'label\tpid\n'
  for name in coreauthd authd applekeystored securityd biometrickitd; do
    while IFS= read -r pid; do
      [[ $pid =~ ^[0-9]+$ ]] && printf '%s\t%s\n' "$name" "$pid"
    done < <(pgrep -x "$name" 2>/dev/null || true)
  done
  while IFS= read -r pid; do
    [[ $pid =~ ^[0-9]+$ ]] && printf '%s\t%s\n' \
      LocalAuthenticationRemoteService "$pid"
  done < <(pgrep -f '/LocalAuthenticationRemoteService($| )' 2>/dev/null || true)
} | awk 'NR == 1 || !seen[$2]++' >"$processes"

pids=()
while IFS= read -r pid; do
  pids+=("$pid")
done < <(awk 'NR > 1 { print $2 }' "$processes")
[[ ${#pids[@]} -gt 0 ]] || {
  echo "No candidate AppleKeyStore caller process is currently running." >&2
  exit 1
}

raw="$work/raw.tsv"
echo "This reads process audit/session metadata only; it changes no state."
if ! sudo "$work/collect" "${pids[@]}" >"$raw"; then
  echo "Warning: at least one candidate exited or could not be inspected." >&2
fi
[[ $(wc -l <"$raw") -gt 1 ]] || {
  echo "No complete process identity record was collected." >&2
  exit 1
}

{
  printf '# captured_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '# boot_uuid=%s\n' "$(sysctl -n kern.bootsessionuuid 2>/dev/null || true)"
  printf '# macos_product_version=%s\n' "$(sw_vers -productVersion)"
  printf '# macos_build_version=%s\n' "$(sw_vers -buildVersion)"
  printf '# Values are boot-scoped private evidence; do not publish or treat them as stable.\n'
  awk -F '\t' 'BEGIN { OFS="\t" }
    NR == FNR { if (FNR > 1) label[$2]=$1; next }
    FNR == 1 { print "process", $0; next }
    { print label[$1], $0 }
  ' "$processes" "$raw"
} >"$output"
chmod 600 "$output"

echo
echo "Created private boot-scoped evidence: $output"
echo "Reboot into Linux, copy it to your home directory, and tell Codex the path."
