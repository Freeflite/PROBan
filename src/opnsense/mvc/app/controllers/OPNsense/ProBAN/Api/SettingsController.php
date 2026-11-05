<?php

namespace OPNsense\ProBAN\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\ProBAN\General;
use OPNsense\ProBAN\Helper;
use OPNsense\Core\Config;
use OPNsense\Core\Backend;

/**
 * ProBAN settings API.
 *
 * Settings live in the General model (config.xml) so they are backed up and
 * survive firmware upgrades. This controller keeps the flat get/set contract the
 * dashboard expects and its custom validators (duration parsing, CIDR checks,
 * reflection-lock on the tarpit target). Firewall rules are no longer created
 * here -- proban_firewall() owns them and regenerates on `filter reload`.
 */
class SettingsController extends ApiControllerBase
{
    public function getAction()
    {
        $mdl = new General();
        $allow = array_values(array_filter(preg_split('/\s+/', (string)$mdl->allowlist)));
        return [
            "enabled" => (int)((string)$mdl->enabled),
            "dry_run" => (int)((string)$mdl->dry_run),
            "wan_if" => (string)$mdl->wan_if,
            "protected_ports" => (string)$mdl->protected_ports,
            "detect_syn" => ((string)$mdl->detect_syn === "0") ? 0 : 1,
            "detect_udp" => (int)((string)$mdl->detect_udp),
            "detect_tcp_scan" => (int)((string)$mdl->detect_tcp_scan),
            "detect_tcp_invalid" => (int)((string)$mdl->detect_tcp_invalid),
            "detect_portscan" => (int)((string)$mdl->detect_portscan),
            "detect_v6_rotation" => (int)((string)$mdl->detect_v6_rotation),
            "v6_rotation_sources" => (int)((string)$mdl->v6_rotation_sources) ?: 8,
            "v6_rotation_hits" => (int)((string)$mdl->v6_rotation_hits) ?: 40,
            "v6_rotation_window" => (int)((string)$mdl->v6_rotation_window) ?: 300,
            "v6_rotation_secs" => (int)((string)$mdl->v6_rotation_secs) ?: 600,
            "portscan_threshold" => (int)((string)$mdl->portscan_threshold) ?: 10,
            "portscan_window" => (int)((string)$mdl->portscan_window) ?: 60,
            "scan_threshold" => (int)((string)$mdl->scan_threshold) ?: 5,
            "scan_window" => (int)((string)$mdl->scan_window) ?: 60,
            "suricata_priority" => (int)((string)$mdl->suricata_priority),
            "suricata_priority_severity" => (int)((string)$mdl->suricata_priority_severity) ?: 1,
            "suricata_priority_secs" => (int)((string)$mdl->suricata_priority_secs) ?: 1800,
            "suricata_priority_sids" => (string)$mdl->suricata_priority_sids,
            "grace_hits" => (int)((string)$mdl->grace_hits),
            "step_secs" => (int)((string)$mdl->step_secs),
            "multiplier" => (float)((string)$mdl->multiplier),
            "max_ban_secs" => (int)((string)$mdl->max_ban_secs),
            "decay_amount" => (int)((string)$mdl->decay_amount),
            "decay_interval" => (int)((string)$mdl->decay_interval),
            "event_retention_days" => (int)((string)$mdl->event_retention_days),
            "offender_amnesia_days" => (int)((string)$mdl->offender_amnesia_days),
            "hide_expired" => (int)((string)$mdl->hide_expired),
            "allowlist" => $allow,
            "sources" => [
                "firewall" => (int)((string)$mdl->src_firewall),
                "suricata" => (int)((string)$mdl->src_suricata),
            ],
            "action" => ((string)$mdl->action === "tarpit") ? "tarpit" : "drop",
            "tarpit_ip" => (string)$mdl->tarpit_ip,
            "tarpit_ports" => (string)$mdl->tarpit_ports,
            "tarpit_ip6" => (string)$mdl->tarpit_ip6,
            "v6_aggregate" => (int)((string)$mdl->v6_aggregate),
            "post_max_action" => ((string)$mdl->post_max_action === "blackhole") ? "blackhole" : "hold",
            "blackhole_hours" => (int)((string)$mdl->blackhole_hours),
            "blackhole_decay" => (int)((string)$mdl->blackhole_decay),
        ];
    }

    public function setAction()
    {
        if (!$this->request->isPost()) {
            return ["status" => "error", "msg" => "POST required"];
        }
        $mdl = new General();
        $req = $this->request;
        $errors = [];

        $mdl->enabled = $req->getPost("enabled", "int", 1) ? "1" : "0";
        $mdl->dry_run = $req->getPost("dry_run", "int", 1) ? "1" : "0";
        $mdl->wan_if = trim((string)$req->getPost("wan_if", "string", ""));
        $mdl->protected_ports = trim((string)$req->getPost("protected_ports", "string", ""));
        $mdl->detect_syn = $req->getPost("detect_syn", "int", ((string)$mdl->detect_syn === "0") ? 0 : 1) ? "1" : "0";
        $mdl->detect_udp = $req->getPost("detect_udp", "int", (int)((string)$mdl->detect_udp)) ? "1" : "0";
        $mdl->detect_tcp_scan = $req->getPost("detect_tcp_scan", "int", (int)((string)$mdl->detect_tcp_scan)) ? "1" : "0";
        $mdl->detect_tcp_invalid = $req->getPost("detect_tcp_invalid", "int", (int)((string)$mdl->detect_tcp_invalid)) ? "1" : "0";
        $mdl->detect_portscan = $req->getPost("detect_portscan", "int", (int)((string)$mdl->detect_portscan)) ? "1" : "0";
        $mdl->detect_v6_rotation = $req->getPost("detect_v6_rotation", "int", (int)((string)$mdl->detect_v6_rotation)) ? "1" : "0";
        $mdl->v6_rotation_sources = (string)max(2, (int)$req->getPost("v6_rotation_sources", "int", (int)((string)$mdl->v6_rotation_sources) ?: 8));
        $mdl->v6_rotation_hits = (string)max((int)((string)$mdl->v6_rotation_sources), (int)$req->getPost("v6_rotation_hits", "int", (int)((string)$mdl->v6_rotation_hits) ?: 40));
        $mdl->v6_rotation_window = (string)max(10, (int)$req->getPost("v6_rotation_window", "int", (int)((string)$mdl->v6_rotation_window) ?: 300));
        $mdl->v6_rotation_secs = (string)max(60, (int)$req->getPost("v6_rotation_secs", "int", (int)((string)$mdl->v6_rotation_secs) ?: 600));
        $mdl->portscan_threshold = (string)max(2, (int)$req->getPost("portscan_threshold", "int", (int)((string)$mdl->portscan_threshold) ?: 10));
        $mdl->portscan_window = (string)max(1, (int)$req->getPost("portscan_window", "int", (int)((string)$mdl->portscan_window) ?: 60));
        $mdl->scan_threshold = (string)max(1, (int)$req->getPost("scan_threshold", "int", (int)((string)$mdl->scan_threshold) ?: 5));
        $mdl->scan_window = (string)max(1, (int)$req->getPost("scan_window", "int", (int)((string)$mdl->scan_window) ?: 60));
        $mdl->suricata_priority = $req->getPost("suricata_priority", "int", (int)((string)$mdl->suricata_priority)) ? "1" : "0";
        $mdl->suricata_priority_severity = (string)max(1, (int)$req->getPost("suricata_priority_severity", "int", (int)((string)$mdl->suricata_priority_severity) ?: 1));
        $mdl->suricata_priority_secs = (string)max(60, (int)$req->getPost("suricata_priority_secs", "int", (int)((string)$mdl->suricata_priority_secs) ?: 1800));
        $mdl->suricata_priority_sids = trim((string)$req->getPost("suricata_priority_sids", "string", (string)$mdl->suricata_priority_sids));
        $mdl->grace_hits = (string)max(1, (int)$req->getPost("grace_hits", "int", 1));
        $mdl->step_secs = (string)max(1, (int)$req->getPost("step_secs", "int", 30));
        $mult = (float)$req->getPost("multiplier", null, "1.5");
        $mdl->multiplier = (string)min(10.0, max(1.0, $mult));
        $mb = Helper::parseDuration($req->getPost("max_ban", "string", "30d"));
        if ($mb < 60) {
            $errors[] = "max ban must be >= 60s (e.g. 30d, 1y 2d)";
        } else {
            $mdl->max_ban_secs = (string)$mb;
        }
        $mdl->decay_amount = (string)max(1, (int)$req->getPost("decay_amount", "int", 30));
        $mdl->decay_interval = (string)max(1, (int)$req->getPost("decay_interval", "int", 60));
        $mdl->event_retention_days = (string)max(0, (int)$req->getPost("event_retention_days", "int", 14));
        $mdl->offender_amnesia_days = (string)max(0, (int)$req->getPost("offender_amnesia_days", "int", 30));
        $mdl->hide_expired = $req->getPost("hide_expired", "int", (int)((string)$mdl->hide_expired)) ? "1" : "0";

        $al = $req->getPost("allowlist");
        if (is_array($al)) {
            $clean = [];
            foreach ($al as $cidr) {
                $cidr = trim($cidr);
                if ($cidr === "") {
                    continue;
                }
                if ($this->validCidr($cidr)) {
                    $clean[] = $cidr;
                } else {
                    $errors[] = "invalid CIDR: " . htmlspecialchars($cidr);
                }
            }
            $mdl->allowlist = implode("\n", array_values(array_unique($clean)));
        }

        $mdl->src_firewall = $req->getPost("src_firewall", "int", 1) ? "1" : "0";
        $mdl->src_suricata = $req->getPost("src_suricata", "int", 1) ? "1" : "0";

        $action = ($req->getPost("action", "string", "drop") === "tarpit") ? "tarpit" : "drop";
        $mdl->action = $action;

        $tip = trim((string)$req->getPost("tarpit_ip", "string", ""));
        if ($tip !== "") {
            if (!filter_var($tip, FILTER_VALIDATE_IP)) {
                $errors[] = "invalid tarpit IP";
            } elseif (!Helper::isPrivateTarget($tip)) {
                $errors[] = "tarpit target must be a private/LAN address (10/8, 172.16/12, 192.168/16, 127/8, 100.64/10, IPv6 ULA). Public targets are blocked to prevent outbound reflection — reach a remote tarpit over a VPN tunnel.";
            } else {
                $mdl->tarpit_ip = $tip;
            }
        }
        if ($action === "tarpit" && (string)$mdl->tarpit_ip === "") {
            $errors[] = "tarpit action requires a private target IP";
        }

        // tarpit_ports: empty => preserve all (catch-all honeypot) ; one => collapse (tarpit) ; list => only those (honeypot)
        $badPorts = [];
        $plist = Helper::parsePorts($req->getPost("tarpit_ports", "string", ""), $badPorts);
        foreach ($badPorts as $bp) {
            $errors[] = "invalid port: " . htmlspecialchars($bp);
        }
        $mdl->tarpit_ports = implode(",", $plist);

        // IPv6 tarpit target: optional. When set it must be a private v6 (ULA) address --
        // same reflection-lock as v4. Blank keeps IPv6 block-only.
        $tip6 = trim((string)$req->getPost("tarpit_ip6", "string", ""));
        if ($tip6 !== "") {
            if (!filter_var($tip6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $errors[] = "invalid IPv6 tarpit target";
            } elseif (!Helper::isPrivateTarget($tip6)) {
                $errors[] = "IPv6 tarpit target must be a private ULA address (fc00::/7). Public targets are blocked to prevent outbound reflection.";
            } else {
                $mdl->tarpit_ip6 = $tip6;
            }
        } else {
            $mdl->tarpit_ip6 = "";
        }
        // /64 escalation threshold: distinct /128 offenders in a /64 before banning the whole /64 (0 = never)
        $mdl->v6_aggregate = (string)max(0, (int)$req->getPost("v6_aggregate", "int", 4));

        // post-max escalation (blackhole). blackhole_decay comes in as a duration string (e.g. "2h").
        $mdl->post_max_action = ($req->getPost("post_max_action", "string", "hold") === "blackhole") ? "blackhole" : "hold";
        $mdl->blackhole_hours = (string)max(1, (int)$req->getPost("blackhole_hours", "int", 12));
        $bd = Helper::parseDuration($req->getPost("blackhole_decay", "string", "2h"));
        $mdl->blackhole_decay = (string)($bd >= 1 ? $bd : 7200);

        if (count($errors)) {
            return ["status" => "error", "msg" => implode("; ", $errors)];
        }

        // model-level validation (numeric ranges, masks)
        $vmsgs = $mdl->performValidation();
        if ($vmsgs->count() > 0) {
            $m = [];
            foreach ($vmsgs as $msg) {
                $m[] = $msg->getField() . ": " . $msg->getMessage();
            }
            return ["status" => "error", "msg" => implode("; ", $m)];
        }

        $mdl->serializeToConfig();
        Config::getInstance()->save();

        // regenerate config.json, apply it immediately with a one-shot engine run, reload
        // firewall rules. NOT a service restart: the supervisor re-reads config.json every
        // cycle, and `proban restart` blocks ~INTERVAL seconds waiting out the supervisor
        // sleep -- which made the Save button look dead on a second save. `proban run` is
        // a single fast engine pass that applies the new config now.
        $backend = new Backend();
        $backend->configdRun("template reload OPNsense/ProBAN");
        $backend->configdRun("proban run");
        $backend->configdRun("filter reload");

        return [
            "status" => "ok",
            "enforcing" => ((string)$mdl->dry_run === "0" && (string)$mdl->enabled === "1"),
        ];
    }

    private function validCidr($cidr)
    {
        if (strpos($cidr, "/") === false) {
            $cidr .= (strpos($cidr, ":") !== false) ? "/128" : "/32";
        }
        list($ip, $mask) = explode("/", $cidr, 2);
        if (!ctype_digit($mask)) {
            return false;
        }
        $mask = (int)$mask;
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $mask >= 0 && $mask <= 32;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $mask >= 0 && $mask <= 128;
        }
        return false;
    }
}
