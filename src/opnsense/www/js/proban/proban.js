// ProBAN dashboard -- bootstrap. PROBAN.T (translated strings) and PROBAN.COLORS are set
// inline by the Volt before these modules load; everything else is a static asset. New
// views/widgets: add a module that hangs off window.PROBAN and init() it here.
window.PROBAN = window.PROBAN || {};
$(function () {
    PROBAN.dashboard.init();
    PROBAN.settings.init();
});
