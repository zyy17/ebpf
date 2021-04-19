#!/bin/bash
# Test the current package under a different kernel.
# Requires virtme and qemu to be installed.
# Examples:
#     Run all tests on a 5.4 kernel
#     $ ./run-tests.sh 5.4
#     Run a subset of tests:
#     $ ./run-tests.sh 5.4 go test ./link

set -eu
set -o pipefail

if [[ "${1:-}" = "--in-vm" ]]; then
  shift

  mount -t bpf bpf /sys/fs/bpf
  mount -t tracefs tracefs /sys/kernel/debug/tracing

  export CGO_ENABLED=0
  export GOFLAGS=-mod=readonly
  export GOPATH=/run/go-path
  export GOPROXY=file:///run/go-path/pkg/mod/cache/download
  export GOSUMDB=off
  export GOCACHE=/run/go-cache

  if [[ -d "/run/input/bpf" ]]; then
    export KERNEL_SELFTESTS="/run/input/bpf"
  fi

  "$@"
  touch "/run/output/success"
  exit 0
fi

if (( $# < 2 )); then
  exec 2>&1
  echo "Usage: $0 <kernel version> <command>"
  echo "Please provide a kernel version and command to run"
  exit 1
fi

# Use sudo if /dev/kvm isn't accessible by the current user.
sudo=""
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  sudo="sudo"
fi
readonly sudo

readonly kernel_version="${1:-}"
if [[ -z "${kernel_version}" ]]; then
  echo "Expecting kernel version as first argument"
  exit 1
fi
shift

readonly kernel="linux-${kernel_version}.bz"
readonly selftests="linux-${kernel_version}-selftests-bpf.bz"
readonly input="$(mktemp -d)"
readonly output="$(mktemp -d)"
readonly tmp_dir="${TMPDIR:-/tmp}"
readonly branch="${BRANCH:-master}"

fetch() {
    echo Fetching "${1}"
    wget -nv -N -P "${tmp_dir}" "https://github.com/cilium/ci-kernels/raw/${branch}/${1}"
}

fetch "${kernel}"

if fetch "${selftests}"; then
  mkdir "${input}/bpf"
  tar --strip-components=4 -xjf "${tmp_dir}/${selftests}" -C "${input}/bpf"
else
  echo "No selftests found, disabling"
fi

printf -v cmd " %q" "$@"

$sudo virtme-run --kimg "${tmp_dir}/${kernel}" --memory 512M --pwd \
  --rw \
  --rwdir="$(dirname "$1")=$(dirname "$1")" \
  --rodir=/run/input="${input}" \
  --rwdir=/run/output="${output}" \
  --rodir=/run/go-path="$(go env GOPATH)" \
  --rwdir=/run/go-cache="$(go env GOCACHE)" \
  --script-sh "PATH=\"$PATH\" $(realpath "$0") --in-vm $cmd" \
  --qemu-opts -smp 2 < /dev/zero # need at least two CPUs for some tests

if [[ ! -e "${output}/success" ]]; then
  exit 1
fi

$sudo rm -r "${input}"
$sudo rm -r "${output}"
