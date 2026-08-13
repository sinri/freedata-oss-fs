#!/bin/sh
set -eu

if [ "$(uname -s)" != Linux ]; then
  echo "linux_e2e.sh requires Linux" >&2
  exit 1
fi
if [ ! -e /dev/fuse ]; then
  echo "/dev/fuse is unavailable; run the container with --privileged" >&2
  exit 1
fi

test_root=$(mktemp -d)
mountpoint_dir="$test_root/mount"
request_log="$test_root/requests.ndjson"
server_log="$test_root/mock.log"
fs_log="$test_root/ossfs.log"
mkdir -p "$mountpoint_dir"
: > "$request_log"

cleanup() {
  if mountpoint -q "$mountpoint_dir"; then
    fusermount3 -u "$mountpoint_dir" || umount "$mountpoint_dir" || true
  fi
  if [ "${fs_pid:-}" ]; then kill "$fs_pid" 2>/dev/null || true; fi
  if [ "${server_pid:-}" ]; then kill "$server_pid" 2>/dev/null || true; fi
  rm -rf "$test_root"
}
trap cleanup EXIT INT TERM

python3 tests/mock_oss.py 19090 "$request_log" > "$server_log" 2>&1 &
server_pid=$!

config_file="$test_root/config.yaml"
sed \
  -e 's#https://oss-cn-hangzhou.aliyuncs.com#http://127.0.0.1:19090#' \
  -e 's#region: cn-hangzhou#region: cn-test#' \
  -e 's#bucket_path: oss://my-bucket/path/used/as/root/#bucket_path: oss://bucket/root/#' \
  -e 's#path_style: false#path_style: true#' \
  -e 's#anonymous: false#anonymous: true#' \
  config.example.yaml > "$config_file"

cargo build --locked
binary_path="${CARGO_TARGET_DIR:-target}/debug/ossfs-ro"
RUST_LOG=info "$binary_path" \
  --config "$config_file" \
  --deny-directory 'cli-hidden/**' \
  "$mountpoint_dir" > "$fs_log" 2>&1 &
fs_pid=$!

attempt=0
while ! mountpoint -q "$mountpoint_dir"; do
  if ! kill -0 "$fs_pid" 2>/dev/null; then
    echo "ossfs-ro exited before mounting" >&2
    cat "$fs_log" >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 100 ]; then
    echo "timed out waiting for FUSE mount" >&2
    cat "$fs_log" >&2
    exit 1
  fi
  sleep 0.1
done

test "$(cat "$mountpoint_dir/public/hello.txt")" = "hello from oss"
test "$(cat "$mountpoint_dir/teams/red/public/info.txt")" = "red public"
test -d "$mountpoint_dir/empty"
test ! -e "$mountpoint_dir/private"
test ! -e "$mountpoint_dir/teams/red/secret"
test ! -e "$mountpoint_dir/archive"
test ! -e "$mountpoint_dir/cli-hidden"

actual_range=$(dd if="$mountpoint_dir/public/large.bin" bs=1 skip=100 count=20 status=none | od -An -tx1 | tr -d ' \n')
expected_range=$(python3 -c 'print(bytes(range(100, 120)).hex())')
test "$actual_range" = "$expected_range"

if sh -c "printf 'overwrite' > '$mountpoint_dir/public/hello.txt'" 2>/dev/null; then
  echo "overwrite unexpectedly succeeded" >&2
  exit 1
fi
if mkdir "$mountpoint_dir/new-directory" 2>/dev/null; then
  echo "mkdir unexpectedly succeeded" >&2
  exit 1
fi
if rm "$mountpoint_dir/public/hello.txt" 2>/dev/null; then
  echo "delete unexpectedly succeeded" >&2
  exit 1
fi
test "$(cat "$mountpoint_dir/public/hello.txt")" = "hello from oss"

if grep -Eq '"method": "(PUT|POST|DELETE|PATCH)"' "$request_log"; then
  echo "filesystem sent a mutating OSS request" >&2
  cat "$request_log" >&2
  exit 1
fi
grep -q 'list-type=2' "$request_log"
grep -q 'root/public/hello.txt' "$request_log"
grep -q 'root/public/large.bin' "$request_log"

echo "Linux FUSE end-to-end test passed"
