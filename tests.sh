#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 || -z $1 ]]; then
  echo "Usage: $0 <vm>" >&2
  exit 1
fi
if ! command -v vmpal >/dev/null 2>&1; then
  echo "tests.sh: vmpal is required; install it and add it to PATH." >&2
  exit 1
fi

vm=$1
cd "$(dirname "$0")"
make debug release
vmpal start "$vm" --wait

for configuration in Debug Release; do
  printf '\nTesting %s\n' "$configuration"
  vmpal exec "$vm" -- /usr/bin/sudo -n /opt/homebrew/bin/brew services stop untcc
  vmpal cp "$PWD/dist/$configuration/untcc" "$vm:/tmp/untcc-e2e-binary"
  vmpal exec "$vm" -- /bin/bash -c 'sudo -n /bin/cp /tmp/untcc-e2e-binary /opt/homebrew/opt/untcc/bin/untcc && rm /tmp/untcc-e2e-binary'
  vmpal exec "$vm" -- /bin/bash -c "$(cat <<'GUEST_TESTS'
set -euo pipefail

if [[ $(/usr/sbin/sysctl -n hw.model) != VirtualMac* ]]; then
  echo "Run guest checks only inside a macOS virtual machine." >&2
  exit 1
fi

brew=/opt/homebrew/bin/brew
formula=untcc
log=/opt/homebrew/var/log/untcc.log
binary=$("$brew" --prefix untcc)/bin/untcc
domain=gui/$(id -u)
label=com.sunnyyoung.untcc.e2e
stage=$(mktemp -d /tmp/untcc-e2e.XXXXXX)
trap 'launchctl bootout "$domain/$label" >/dev/null 2>&1 || true; rm -rf "$stage"' EXIT

cat > "$stage/probe.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key><array><string>$binary</string><string>probe</string></array>
  <key>ThrottleInterval</key><integer>0</integer>
  <key>StandardOutPath</key><string>$stage/permissions.json</string>
  <key>StandardErrorPath</key><string>$stage/permissions.stderr</string>
</dict></plist>
PLIST
launchctl bootstrap "$domain" "$stage/probe.plist"

check_permissions() {
  local expected=$1 expected_status=1 attempt actual_status key actual
  if [[ "$expected" == true ]]; then expected_status=0; fi
  : > "$stage/permissions.json"
  launchctl kickstart -k "$domain/$label"
  for ((attempt = 0; attempt < 100; attempt++)); do
    launchctl print "$domain/$label" > "$stage/probe.status"
    if grep -q '^[[:space:]]*state = not running$' "$stage/probe.status"; then break; fi
    sleep 0.1
  done
  if ! grep -q '^[[:space:]]*state = not running$' "$stage/probe.status"; then
    echo "Timed out waiting for untcc probe to exit." >&2
    cat "$stage/probe.status" "$stage/permissions.stderr" >&2
    exit 1
  fi
  if [[ ! -s "$stage/permissions.json" ]]; then
    echo "Expected permission JSON from untcc probe; got no output." >&2
    cat "$stage/permissions.stderr" >&2
    exit 1
  fi
  actual_status=$(awk '/^[[:space:]]*last exit code =/ { print $5; exit }' "$stage/probe.status")
  if [[ "$actual_status" != "$expected_status" ]]; then
    echo "Expected probe exit code $expected_status; got $actual_status." >&2
    exit 1
  fi
  for key in accessibility screenCapture; do
    actual=$(/usr/bin/plutil -extract "$key" raw -o - "$stage/permissions.json")
    if [[ "$actual" != "$expected" ]]; then
      echo "Expected $key=$expected; got $actual." >&2
      exit 1
    fi
  done
}

log_position() {
  if [[ -f "$log" ]]; then wc -l < "$log"; else echo 0; fi
}

wait_ready() {
  local first_line=$(($1 + 1)) attempt ready pids pid
  for ((attempt = 0; attempt < 100; attempt++)); do
    ready=true
    pids=$(pgrep -x tccd || true)
    [[ -n "$pids" ]] || ready=false
    tail -n +"$first_line" "$log" > "$stage/ready.log"
    for pid in $pids; do
      if ! grep -q "ready pid=$pid$" "$stage/ready.log"; then
        ready=false
      fi
    done
    if $ready && pgrep -x untcc >/dev/null; then return; fi
    sleep 0.1
  done
  tail -n 20 "$log" >&2
  echo "Timed out waiting for tccd hooks." >&2
  exit 1
}

snapshot_resources() {
  local pid
  for pid in $(pgrep -x tccd | sort -n); do
    sudo -n vmmap -wide "$pid" > "$stage/vmmap.$pid"
    printf '%s ' "$pid"
    awk '/^VM_ALLOCATE .*SM=/ { allocations++ }
         /^Stack[[:space:]]+[[:xdigit:]]+-.*SM=PRV/ && !/thread [0-9]+/ { stacks++ }
         END { print allocations + 0, stacks + 0 }' "$stage/vmmap.$pid"
  done
}

sudo -n "$brew" services stop "$formula"
sudo -n launchctl kickstart -k system/com.apple.tccd.system
sudo -n launchctl kickstart -k "$domain/com.apple.tccd"
check_permissions false
echo "PASS: fresh tccd denies both permissions; probe exits 1"

if "$binary" > "$stage/nonroot.log" 2>&1; then
  echo "Expected untcc to reject a non-root user." >&2
  exit 1
fi
grep -q 'root required' "$stage/nonroot.log"
echo "PASS: non-root execution is rejected"

if "$binary" probe extra > "$stage/arguments.log" 2>&1; then
  echo "Expected untcc probe to reject extra arguments." >&2
  exit 1
fi
grep -q '^Usage:' "$stage/arguments.log"
echo "PASS: probe rejects extra arguments"

log_start=$(log_position)
sudo -n "$brew" services start "$formula"
wait_ready "$log_start"
check_permissions true
echo "PASS: Homebrew service grants both permissions; probe exits 0"

log_start=$(log_position)
if (wait_ready "$log_start") > "$stage/stale-ready.log" 2>&1; then
  echo "Historical ready messages must not satisfy a new readiness check." >&2
  exit 1
fi
grep -q 'Timed out waiting for tccd hooks.' "$stage/stale-ready.log"
echo "PASS: historical ready messages are rejected"

log_start=$(log_position)
sudo -n "$brew" services restart "$formula"
wait_ready "$log_start"
check_permissions true
echo "PASS: service restart preserves working hooks"

snapshot_resources > "$stage/resources.before"
for ((restart = 0; restart < 3; restart++)); do
  log_start=$(log_position)
  sudo -n "$brew" services restart "$formula"
  wait_ready "$log_start"
  check_permissions true
done
snapshot_resources > "$stage/resources.after"
diff -u "$stage/resources.before" "$stage/resources.after"
echo "PASS: repeated starts preserve permissions without accumulating mappings or thread stacks"

log_start=$(log_position)
sudo -n launchctl kickstart -k system/com.apple.tccd.system
sudo -n launchctl kickstart -k "$domain/com.apple.tccd"
wait_ready "$log_start"
check_permissions true
echo "PASS: tccd restart is handled"

sudo -n "$brew" services stop "$formula"
check_permissions true
sudo -n launchctl kickstart -k system/com.apple.tccd.system
sudo -n launchctl kickstart -k "$domain/com.apple.tccd"
check_permissions false
echo "PASS: stop preserves existing hooks; fresh tccd restores permission checks"

log_start=$(log_position)
sudo -n "$brew" services start "$formula"
wait_ready "$log_start"
check_permissions true
echo "PASS: service is running and ready"
GUEST_TESTS
)"
done
