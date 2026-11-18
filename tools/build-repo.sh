#!/bin/sh
# Turn a built os-proban package into the signed package repository that GitHub Pages
# serves at https://freeflite.github.io/PROBan/ (what OPNsense firewalls pull updates from).
#
#   PKG_SIGNING_KEY_B64=... tools/build-repo.sh <os-proban-X.Y.Z.pkg> <site-dir>
#
# PKG_SIGNING_KEY_B64 is the repository's RSA private key (PEM), base64-encoded on one line.
# It only ever touches disk as a mode-600 temp file that is removed on exit.
#
# Runs on FreeBSD (it needs 'pkg repo'). The repository holds only the newest package:
# firewalls always upgrade to the latest release, like OPNsense's own repository.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PUBKEY=$ROOT/pkg-repo/proban.pub

fail() { echo "build-repo: $*" >&2; exit 1; }

[ $# -eq 2 ] || fail "usage: build-repo.sh <package> <site-dir>"
PKGFILE=$1
SITE=$2
[ -f "$PKGFILE" ] || fail "no such package: $PKGFILE"
[ -n "${PKG_SIGNING_KEY_B64:-}" ] || fail "PKG_SIGNING_KEY_B64 is not set"

umask 077
TMP=$(mktemp -d -t proban-repo)
trap 'rm -rf "$TMP"' EXIT

printf '%s' "$PKG_SIGNING_KEY_B64" | openssl base64 -d -A > "$TMP/key.pem"
openssl rsa -in "$TMP/key.pem" -pubout -out "$TMP/key.pub" 2> /dev/null ||
	fail "PKG_SIGNING_KEY_B64 is not a valid RSA private key"
# Signing with any other key would break every firewall that trusts proban.pub.
cmp -s "$TMP/key.pub" "$PUBKEY" || fail "the signing key does not match pkg-repo/proban.pub"

umask 022
rm -rf "$SITE"
mkdir -p "$SITE/repo/All"
cp "$PKGFILE" "$SITE/repo/All/"
pkg repo "$SITE/repo" "rsa:$TMP/key.pem"
cp "$PUBKEY" "$ROOT/pkg-repo/ProBAN.conf" "$ROOT/pkg-repo/index.html" "$SITE/"

# Read it back the way a firewall will: signature checked against proban.pub, and the
# package listed. Uses a throwaway pkg database so the build host's own is untouched.
mkdir -p "$TMP/repos" "$TMP/db"
cat > "$TMP/repos/ProBAN.conf" << EOF
ProBAN: {
  url: "file://$(cd "$SITE/repo" && pwd)",
  signature_type: "pubkey",
  pubkey: "$PUBKEY",
  mirror_type: "none",
  enabled: yes
}
EOF
NAME=$(pkg query -F "$PKGFILE" '%n-%v')
REPO_PKG=$(REPOS_DIR="$TMP/repos" PKG_DBDIR="$TMP/db" sh -c \
    'pkg update -q -f -r ProBAN && pkg rquery -r ProBAN "%n-%v"')
[ "$REPO_PKG" = "$NAME" ] || fail "repository lists '$REPO_PKG', expected $NAME"

echo "build-repo: signed repository for $NAME in $SITE"
