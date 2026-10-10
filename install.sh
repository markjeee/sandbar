#!/bin/sh
# Installs checkout source or this fixed release. Caddy is installed separately.
set -eu
umask 077

version='v0.1.0-beta.2'
bin_dir=${HOME:?HOME must select your user directory}/.local/bin
while [ "$#" -gt 0 ]; do
    case "$1" in
        --bin-dir)
            [ "$#" -ge 2 ] && [ -n "$2" ] || { echo '--bin-dir requires a directory' >&2; exit 1; }
            bin_dir=$2
            shift 2
            ;;
        --help)
            echo 'Usage: sh install.sh [--bin-dir <directory>]'
            exit 0
            ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; exit 1 ;;
    esac
done
case "$bin_dir" in /*) ;; *) bin_dir="$(pwd)/$bin_dir" ;; esac

case "$(uname -s):$(uname -m)" in
    Linux:x86_64|Linux:amd64) ;;
    *) echo 'Sandbar supports Linux amd64 only.' >&2; exit 1 ;;
esac

source_dir=
if [ -f "$0" ]; then
    script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
    if [ -f "$script_dir/go.mod" ] && [ -f "$script_dir/main.go" ]; then
        source_dir=$script_dir
    fi
fi
work_dir=$(mktemp -d)
install_tmp=
cleanup() {
    [ -z "$install_tmp" ] || rm -f "$install_tmp"
    rm -rf "$work_dir"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

if [ -n "$source_dir" ]; then
    command -v go >/dev/null 2>&1 || { echo 'Checkout installation requires Go. See go.mod for the version.' >&2; exit 1; }
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go -C "$source_dir" build -trimpath -o "$work_dir/sandbar" .
else
    archive="sandbar_${version}_linux_amd64.tar.gz"
    base_url="https://github.com/markjeee/sandbar/releases/download/$version"
    curl -fsSL "$base_url/$archive" -o "$work_dir/$archive"
    curl -fsSL "$base_url/SHA256SUMS" -o "$work_dir/SHA256SUMS"
    # Check exactly the selected package, without trusting other manifest paths.
    awk -v name="$archive" '$2 == name { print $1 "  " $2; count++ } END { if (count != 1) exit 1 }' \
        "$work_dir/SHA256SUMS" > "$work_dir/package.sha256"
    (cd "$work_dir" && sha256sum -c package.sha256)
    tar -xzf "$work_dir/$archive" -C "$work_dir" sandbar
    [ -f "$work_dir/sandbar" ] && [ ! -L "$work_dir/sandbar" ] || { echo 'Release package has no regular sandbar executable.' >&2; exit 1; }
fi

mkdir -p "$bin_dir"
[ ! -d "$bin_dir/sandbar" ] || { echo 'Installation destination is a directory: sandbar' >&2; exit 1; }
# This file shares the destination filesystem, so rename replaces atomically.
install_tmp=$(mktemp "$bin_dir/.sandbar.XXXXXX")
cat "$work_dir/sandbar" > "$install_tmp"
chmod 755 "$install_tmp"
mv -f "$install_tmp" "$bin_dir/sandbar"
install_tmp=
printf 'Installed Sandbar to %s/sandbar\n' "$bin_dir"
