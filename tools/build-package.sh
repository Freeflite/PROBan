#!/bin/sh
# Build the os-proban package with OPNsense's own plugin build system.
#
# Runs on FreeBSD: the CI's FreeBSD VM, or any FreeBSD/OPNsense box with git installed.
#
#   tools/build-package.sh [output-dir]        (default: dist/)
#
# Set TAG=vX.Y.Z to fail unless the Makefile's PLUGIN_VERSION matches the tag.
set -eu

PLUGINS_REPO=https://github.com/opnsense/plugins
# Pinned so a change upstream can't silently change how the package is built. Bump it
# deliberately (and rebuild/test) when OPNsense's plugin build system changes.
PLUGINS_COMMIT=5ab1f3fe2a273dd56e7b653b62fa74bdea8a2396

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$ROOT/dist}

fail() { echo "build-package: $*" >&2; exit 1; }

[ "$(uname -s)" = FreeBSD ] || fail "must run on FreeBSD"
# Without a bootstrapped pkg, OPNsense's Makefile quietly skips 'pkg create'.
[ -x /usr/local/sbin/pkg ] || fail "pkg is not bootstrapped (run: pkg bootstrap -y)"
command -v git > /dev/null || fail "git is required (pkg install -y git)"

VERSION=$(sed -n 's/^PLUGIN_VERSION=[[:space:]]*//p' "$ROOT/Makefile")
[ -n "$VERSION" ] || fail "no PLUGIN_VERSION in Makefile"
if [ -n "${TAG:-}" ] && [ "$TAG" != "v$VERSION" ]; then
	fail "tag $TAG does not match Makefile version $VERSION"
fi

# Every script with a shebang must be committed executable. A non-executable rc.d
# launcher is what made the service fail with exit status 126 in 0.1.2.
NOEXEC=$(cd "$ROOT/src" && find . -type f ! -perm -u+x -exec sh -c \
    'head -c 2 "$1" | grep -q "^#!" && echo "$1"' _ {} \;)
[ -z "$NOEXEC" ] || fail "scripts with a shebang but no executable bit:
$NOEXEC"

WORK=$(mktemp -d -t proban-build)
trap 'rm -rf "$WORK"' EXIT

git init -q "$WORK/plugins"
git -C "$WORK/plugins" fetch -q --depth 1 "$PLUGINS_REPO" "$PLUGINS_COMMIT"
git -C "$WORK/plugins" checkout -q FETCH_HEAD

DIR=$WORK/plugins/security/proban
mkdir -p "$DIR"
cp -Rp "$ROOT/Makefile" "$ROOT/pkg-descr" "$ROOT/src" "$DIR/"
# Package script fragments (+POST_INSTALL.post etc.) live next to the Makefile.
for f in "$ROOT"/+*; do
	[ -f "$f" ] && cp -p "$f" "$DIR/"
done

# Stamp the package's version info with this repo's commit, not opnsense/plugins'.
# (In CI, git may refuse a checkout owned by another user, so prefer GITHUB_SHA.)
if [ -n "${GITHUB_SHA:-}" ]; then
	HASH=$(echo "$GITHUB_SHA" | cut -c1-9)
else
	HASH=$(git -C "$ROOT" rev-parse --short=9 HEAD 2> /dev/null || echo unknown)
fi
make -C "$DIR" package PLUGIN_HASH="$HASH"

PKGFILE=$DIR/work/pkg/os-proban-$VERSION.pkg
[ -f "$PKGFILE" ] || fail "expected $PKGFILE, found: $(ls "$DIR/work/pkg" 2> /dev/null)"

# Check what was actually built before anyone can install it.
NAME=$(pkg query -F "$PKGFILE" '%n')
PKGVER=$(pkg query -F "$PKGFILE" '%v')
ABI=$(pkg query -F "$PKGFILE" '%q')
[ "$NAME" = os-proban ] || fail "package is named $NAME, expected os-proban"
[ "$PKGVER" = "$VERSION" ] || fail "package version is $PKGVER, expected $VERSION"
[ "$ABI" = "FreeBSD:*:*" ] || fail "package ABI is $ABI, expected FreeBSD:*:*"
for f in /usr/local/etc/rc.d/proban \
    /usr/local/opnsense/scripts/OPNsense/Parabolic/engine.py \
    /usr/local/opnsense/scripts/OPNsense/Parabolic/proban_supervise.sh; do
	MODE=$(pkg query -F "$PKGFILE" '%Fp %Fm' | awk -v f="$f" '$1 == f { print $2 }')
	# The owner digit is third from the end (755 or 0755); it must include execute.
	case "$MODE" in
	*[1357][0-7][0-7]) ;;
	*) fail "$f is not executable in the package (mode '$MODE')" ;;
	esac
done

# Without this hook an upgrade leaves the old engine running until the next reboot.
pkg info -R -F "$PKGFILE" | grep -q 'Restarting ProBAN engine' ||
	fail "the package's post-install script does not restart the engine"

mkdir -p "$OUT"
cp "$PKGFILE" "$OUT/"
echo "build-package: built $OUT/os-proban-$VERSION.pkg ($ABI, commit $HASH)"
