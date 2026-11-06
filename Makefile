# OPNsense plugin: ProBAN. Drops into opnsense/plugins/security/proban/.

PLUGIN_NAME=		proban
PLUGIN_VERSION=		0.1.3
PLUGIN_COMMENT=		Progressive/parabolic banning of abusive IPs, with tarpit & honeypot
PLUGIN_MAINTAINER=	83433431+Freeflite@users.noreply.github.com
PLUGIN_WWW=		https://github.com/Freeflite/PROBan
# python3 is provided by the OPNsense base (configd runs on it); no extra pkg dep needed.

.include "../../Mk/plugins.mk"
