#!/bin/sh
# Installs checkout source or this fixed release. Caddy is installed separately.
set -eu
umask 077

version='v0.1.0-beta.2'
case "$(uname -s):$(uname -m)" in
    Linux:x86_64|Linux:amd64) target_os=linux; target_arch=amd64; bin_dir=${HOME:?HOME must select your user directory}/.local/bin ;;
    Darwin:arm64) target_os=darwin; target_arch=arm64; bin_dir=/usr/local/bin ;;
    *) echo 'Sandbar supports Linux amd64 and macOS arm64 only.' >&2; exit 1 ;;
esac
while [ "$#" -gt 0 ]; do
    case "$1" in
        --bin-dir)
            [ "$#" -ge 2 ] && [ -n "$2" ] || { echo '--bin-dir requires a directory' >&2; exit 1; }
            bin_dir=$2
            shift 2
            ;;
        --help)
            printf 'Usage: sh install.sh [--bin-dir <directory>]\nDefault executable: %s/sandbar\n' "$bin_dir"
            exit 0
            ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; exit 1 ;;
    esac
done
case "$bin_dir" in /*) ;; *) bin_dir="$(pwd)/$bin_dir" ;; esac

source_dir=
if [ -f "$0" ]; then
    script_dir=$(CDPATH='' cd -P "$(dirname "$0")" && pwd)
    if [ -f "$script_dir/go.mod" ] && [ -f "$script_dir/main.go" ]; then
        source_dir=$script_dir
    fi
fi
if [ -z "$source_dir" ] && [ "$target_os" = darwin ] && [ "$version" = v0.1.0-beta.2 ]; then
    echo 'Sandbar v0.1.0-beta.2 has no macOS release asset. Install from a checkout until a native release is published.' >&2
    exit 1
fi
work_dir=$(mktemp -d)
install_tmp=
publish_with_sudo=0
publish() {
    if [ "$publish_with_sudo" = 1 ]; then sudo "$@"; else "$@"; fi
}
cleanup() {
    [ -z "$install_tmp" ] || publish rm -f "$install_tmp"
    rm -rf "$work_dir"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

if [ -n "$source_dir" ]; then
    command -v go >/dev/null 2>&1 || { echo 'Checkout installation requires Go. See go.mod for the version.' >&2; exit 1; }
    cgo_enabled=0
    if [ "$target_os" = darwin ]; then
        command -v xcrun >/dev/null 2>&1 || { echo 'macOS source builds require Xcode Command Line Tools. Run xcode-select --install.' >&2; exit 1; }
        CC=$(xcrun --find clang) && [ -x "$CC" ] || { echo 'macOS source builds require SDK clang. Run xcode-select --install.' >&2; exit 1; }
        SDKROOT=$(xcrun --sdk macosx --show-sdk-path) && [ -d "$SDKROOT" ] || { echo 'macOS source builds require the macOS SDK. Run xcode-select --install.' >&2; exit 1; }
        export CC SDKROOT
        cgo_enabled=1
    fi
    CGO_ENABLED="$cgo_enabled" GOOS="$target_os" GOARCH="$target_arch" go -C "$source_dir" build -trimpath -o "$work_dir/sandbar" .
else
    archive="sandbar_${version}_${target_os}_${target_arch}.tar.gz"
    base_url="https://github.com/markjeee/sandbar/releases/download/$version"
    curl -fsSL "$base_url/$archive" -o "$work_dir/$archive"
    curl -fsSL "$base_url/SHA256SUMS" -o "$work_dir/SHA256SUMS"
    # Check exactly the selected package, without trusting other manifest paths.
    awk -v name="$archive" '
        $2 == name {
            if (NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-fA-F]/) exit 1
            print $1 "  " $2
            count++
        }
        END { if (count != 1) exit 1 }
    ' "$work_dir/SHA256SUMS" > "$work_dir/package.sha256"
    if [ "$target_os" = linux ]; then
        (cd "$work_dir" && sha256sum -c package.sha256)
    else
        (cd "$work_dir" && shasum -a 256 -c package.sha256)
    fi
    tar -xzf "$work_dir/$archive" -C "$work_dir" sandbar
    [ -f "$work_dir/sandbar" ] && [ ! -L "$work_dir/sandbar" ] || { echo 'Release package has no regular sandbar executable.' >&2; exit 1; }
fi

# Build and download as the caller. Elevate only final macOS publication if needed.
permission_dir=$bin_dir
while [ ! -d "$permission_dir" ]; do permission_dir=$(dirname "$permission_dir"); done
if [ "$target_os" = darwin ] && [ ! -w "$permission_dir" ]; then
    command -v sudo >/dev/null 2>&1 || { echo 'Destination requires write access. Use --bin-dir to select a writable directory.' >&2; exit 1; }
    publish_with_sudo=1
fi
if [ "$publish_with_sudo" = 1 ]; then
    # New executable directories must remain traversable by the caller.
    (umask 022; publish mkdir -p -m 755 "$bin_dir")
else
    publish mkdir -p "$bin_dir"
fi
[ ! -d "$bin_dir/sandbar" ] || { echo 'Installation destination is a directory: sandbar' >&2; exit 1; }
# This file shares the destination filesystem, so rename replaces atomically.
install_tmp=$(publish mktemp "$bin_dir/.sandbar.XXXXXX")
publish cp "$work_dir/sandbar" "$install_tmp"
publish chmod 755 "$install_tmp"
publish mv -f "$install_tmp" "$bin_dir/sandbar"
install_tmp=
printf 'Installed Sandbar to %s/sandbar\n' "$bin_dir"
