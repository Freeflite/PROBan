<?php
namespace OPNsense\ProBAN\Api;

use OPNsense\ProBAN\Helper;

class OverviewController extends \OPNsense\Base\ApiControllerBase
{
    private function db()
    {
        $p = "/var/log/parabolic/offenders.db";
        if (!file_exists($p)) return null;
        $db = new \SQLite3($p, SQLITE3_OPEN_READONLY);
        $db->busyTimeout(3000);
        return $db;
    }
    public function statsAction()
    {
        try {
            $db = $this->db();
            if ($db === null) return ["total"=>0,"active"=>0,"events24h"=>0,"mode"=>"no-data","levels"=>[]];
            $now = time();
            $cfg = @json_decode(@file_get_contents("/usr/local/opnsense/scripts/OPNsense/Parabolic/config.json"), true);
            $mode = "enforcing";
            if (empty($cfg["enabled"])) $mode = "disabled";
            elseif (!empty($cfg["dry_run"])) $mode = "dry-run";
            $levels = [];
            $r = $db->query("SELECT level,COUNT(*) c FROM offenders WHERE ban_secs>0 GROUP BY level ORDER BY level");
            while ($x = $r->fetchArray(SQLITE3_ASSOC)) $levels[(string)$x['level']] = (int)$x['c'];
            $tamper = (string)@$db->querySingle("SELECT v FROM state WHERE k='tamper'");
            $out = [
                "total" => (int)$db->querySingle("SELECT COUNT(*) FROM offenders"),
                "active" => (int)$db->querySingle("SELECT COUNT(*) FROM offenders WHERE ban_secs>0"),
                "events24h" => (int)$db->querySingle("SELECT COUNT(*) FROM events WHERE ts > ".($now-86400)),
                "mode" => $mode,
                "levels" => $levels,
                "tamper" => $tamper
            ];
            $db->close();
            return $out;
        } catch (\Throwable $e) { return ["total"=>0,"active"=>0,"events24h"=>0,"mode"=>"busy","levels"=>[],"skip"=>true]; }
    }
    public function offendersAction()
    {
        try {
            $db = $this->db();
            if ($db === null) return ["rows"=>[], "total" => 0];

            $limit = (int)$this->request->getQuery('limit', 'int', 25);
            $offset = (int)$this->request->getQuery('offset', 'int', 0);
            $sort = $this->request->getQuery('sort', 'string', 'ban_secs');
            $dir = (int)$this->request->getQuery('dir', 'int', -1);
            $family = (int)$this->request->getQuery('family', 'int', 0);

            $allowedSort = ['ip', 'hits', 'ban_secs', 'level', 'blocked_until'];
            if (!in_array($sort, $allowedSort)) $sort = 'ban_secs';
            $order = $dir < 0 ? 'DESC' : 'ASC';

            $where = '';
            if ($family === 4) {
                $where = " WHERE ip NOT LIKE '%:%' ";
            } elseif ($family === 6) {
                $where = " WHERE ip LIKE '%:%' ";
            }

            $total = (int)$db->querySingle("SELECT COUNT(*) FROM offenders" . $where);

            if ($limit <= 0 || $limit > 10000) $limit = 10000;
            if ($offset < 0) $offset = 0;

            $sql = "SELECT ip,hits,ban_secs,level,blocked_until,reasons FROM offenders" . $where . " ORDER BY $sort $order LIMIT $limit OFFSET $offset";
            $r = $db->query($sql);
            $rows = [];
            while ($x = $r->fetchArray(SQLITE3_ASSOC)) {
                $l = array_values(array_filter(explode("\n", (string)$x['reasons'])));
                $x['last_reason'] = count($l) ? end($l) : "";
                $x['ban_secs'] = (int)round($x['ban_secs']);
                unset($x['reasons']); $rows[] = $x;
            }
            $db->close();
            return ["rows" => $rows, "total" => $total];
        } catch (\Throwable $e) { return ["rows"=>[],"total"=>0,"skip"=>true]; }
    }
    public function timelineAction($bucket = 300, $window = 10800, $end = 0)
    {
        try {
            $bucket = max(60, (int)$bucket);
            $window = max($bucket * 2, (int)$window);
            $end = (int)$end; if ($end <= 0) $end = time();
            $start = $end - $window;
            $db = $this->db();
            if ($db === null) return ["buckets"=>[],"bucket"=>$bucket,"window"=>$window,"end"=>$end];
            $s = $db->prepare("SELECT (ts/$bucket)*$bucket h, COUNT(*) c FROM events WHERE ts >= :a AND ts < :b GROUP BY h");
            $s->bindValue(":a", $start, SQLITE3_INTEGER);
            $s->bindValue(":b", $end, SQLITE3_INTEGER);
            $r = $s->execute();
            $map = [];
            while ($x = $r->fetchArray(SQLITE3_ASSOC)) $map[(int)$x['h']] = (int)$x['c'];
            $b = []; $t0 = intval($start / $bucket) * $bucket;
            for ($t = $t0; $t < $end; $t += $bucket) $b[] = ["t"=>$t*1000, "c"=>isset($map[$t])?$map[$t]:0];
            $db->close();
            return ["buckets"=>$b,"bucket"=>$bucket,"window"=>$window,"end"=>$end];
        } catch (\Throwable $e) { return ["buckets"=>[],"skip"=>true]; }
    }
    public function eventsAction($ip = null)
    {
        try {
            $db = $this->db();
            if ($db === null || $ip === null) return ["rows"=>[]];
            $s = $db->prepare("SELECT ts,source,reason FROM events WHERE ip=:ip ORDER BY ts DESC LIMIT 100");
            $s->bindValue(":ip", $ip, SQLITE3_TEXT);
            $r = $s->execute(); $rows = [];
            while ($x = $r->fetchArray(SQLITE3_ASSOC)) $rows[] = $x;
            $db->close();
            return ["ip"=>$ip, "rows"=>$rows];
        } catch (\Throwable $e) { return ["ip"=>$ip,"rows"=>[],"skip"=>true]; }
    }
    // TCP connect-probe the tarpit/honeypot target so a mode swap can't silently redirect into a void.
    public function healthAction()
    {
        try {
            $cfg = @json_decode(@file_get_contents("/usr/local/opnsense/scripts/OPNsense/Parabolic/config.json"), true);
            if (!is_array($cfg)) return ["status"=>"n/a"];
            if (($cfg["action"] ?? "drop") !== "tarpit") return ["status"=>"n/a","reason"=>"drop mode"];
            $ip = $cfg["tarpit_ip"] ?? "";
            if ($ip === "") return ["status"=>"n/a","reason"=>"no target"];
            $ports = Helper::parsePorts($cfg["tarpit_ports"] ?? "");
            $defaulted = false;
            if (empty($ports)) { $ports = [22,23,80,443,445,8080,8443]; $defaulted = true; }   // honeypot catch-all: probe common services
            $results = []; $up = 0;
            foreach ($ports as $p) {
                $errno = 0; $errstr = "";
                $fp = @fsockopen($ip, $p, $errno, $errstr, 1.0);
                $ok = false;
                if ($fp) { $ok = true; @fclose($fp); }
                $results[] = ["port"=>$p, "up"=>$ok];
                if ($ok) $up++;
            }
            $total = count($ports);
            $status = ($up === 0) ? "down" : (($up >= ceil($total/2)) ? "healthy" : "degraded");
            return ["status"=>$status, "ip"=>$ip, "up"=>$up, "total"=>$total, "defaulted"=>$defaulted, "ports"=>$results];
        } catch (\Throwable $e) { return ["status"=>"error"]; }
    }
}
