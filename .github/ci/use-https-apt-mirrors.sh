#!/bin/sh
set -eu
apt_root=${1:-/etc/apt}
for source in "$apt_root"/sources.list "$apt_root"/sources.list.d/*.list "$apt_root"/sources.list.d/*.sources; do
    if [ -f "$source" ]; then
        sed \
            -e 's|http://archive.ubuntu.com/|https://archive.ubuntu.com/|g' \
            -e 's|http://security.ubuntu.com/|https://security.ubuntu.com/|g' \
            -e 's|http://ports.ubuntu.com/|https://ports.ubuntu.com/|g' \
            -e 's|http://deb.debian.org/|https://deb.debian.org/|g' \
            -e 's|http://security.debian.org/|https://security.debian.org/|g' \
            "$source" > "${source}.ci-https"
        cat "${source}.ci-https" > "$source"
        rm -f "${source}.ci-https"
    fi
done
