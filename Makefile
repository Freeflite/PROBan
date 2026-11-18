# OPNsense plugin: ProBAN. Drops into opnsense/plugins/security/proban/.

PLUGIN_NAME=		proban
PLUGIN_VERSION=		0.1.6
PLUGIN_COMMENT=		Progressive/parabolic banning of abusive IPs, with tarpit & honeypot
PLUGIN_MAINTAINER=	83433431+Freeflite@users.noreply.github.com
PLUGIN_WWW=		https://github.com/Freeflite/PROBan
# python3 is provided by the OPNsense base (configd runs on it); no extra pkg dep needed.

# Build the release package name (os-proban). The opnsense/plugins master branch otherwise
# forces os-proban-devel, which the firmware Plugins page hides on a normal (non-devel) firewall.
PLUGIN_DEVEL=
# ProBAN is PHP/Python/templates only, nothing compiled, so one package installs on every
# FreeBSD release OPNsense runs (abi FreeBSD:*:*).
PLUGIN_NO_ABI=		yes

.include "../../Mk/plugins.mk"
