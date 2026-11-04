<?php
namespace OPNsense\ProBAN\Api;

use OPNsense\ProBAN\General;
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
    private function eventHits($db)
    {
        $columns = $db->query("PRAGMA table_info(events)");
        while ($column = $columns->fetchArray(SQLITE3_ASSOC)) {
            if ($column['name'] === 'hits') return 'hits';
        }
        return '1';
    }
    private function offendersWhere($family = 0, $search = '')
    {
        $conditions = [];
        $model = new General();
        if ((string)$model->hide_expired === '1') $conditions[] = 'blocked_until > ' . time();
        if ($family === 4) $conditions[] = "ip NOT LIKE '%:%'";
        elseif ($family === 6) $conditions[] = "ip LIKE '%:%'";
        if ($search !== '') $conditions[] = 'instr(lower(ip), lower(:search)) > 0';
        return count($conditions) ? ' WHERE ' . implode(' AND ', $conditions) : '';
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
            $counterError = (string)$db->querySingle("SELECT v FROM state WHERE k='counter_error'");
            $eventHits = $this->eventHits($db);
            $out = [
                "total" => (int)$db->querySingle("SELECT COUNT(*) FROM offenders" . $this->offendersWhere()),
                "active" => (int)$db->querySingle("SELECT COUNT(*) FROM offenders WHERE ban_secs>0"),
                "events24h" => (int)$db->querySingle("SELECT COALESCE(SUM({$eventHits}),0) FROM events WHERE ts > ".($now-86400)),
                "mode" => $mode,
                "levels" => $levels,
                "tamper" => $tamper,
                "counter_error" => $counterError
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
            $search = trim((string)$this->request->getQuery('search', 'string', ''));

            $allowedSort = ['ip', 'hits', 'last_seen', 'ban_secs', 'level', 'blocked_until'];
            if (!in_array($sort, $allowedSort)) $sort = 'ban_secs';
            $order = $dir < 0 ? 'DESC' : 'ASC';

            $where = $this->offendersWhere($family, $search);

            $count = $db->prepare("SELECT COUNT(*) FROM offenders" . $where);
            if ($search !== '') $count->bindValue(':search', $search, SQLITE3_TEXT);
            $total = (int)$count->execute()->fetchArray(SQLITE3_NUM)[0];

            if ($limit <= 0 || $limit > 10000) $limit = 10000;
            if ($offset < 0) $offset = 0;

            $sql = "SELECT ip,hits,last_seen,ban_secs,level,blocked_until,reasons FROM offenders" . $where . " ORDER BY $sort $order LIMIT $limit OFFSET $offset";
            $statement = $db->prepare($sql);
            if ($search !== '') $statement->bindValue(':search', $search, SQLITE3_TEXT);
            $r = $statement->execute();
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
            $eventHits = $this->eventHits($db);
            $s = $db->prepare("SELECT (ts/$bucket)*$bucket h, SUM({$eventHits}) c FROM events WHERE ts >= :a AND ts < :b GROUP BY h");
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
            $limit = max(1, min(500, (int)$this->request->getQuery('limit', 'int', 100)));
            $offset = max(0, (int)$this->request->getQuery('offset', 'int', 0));
            $through = max(0, (int)$this->request->getQuery('through', 'int', 0));
            if ($ip === null) $ip = trim((string)$this->request->getQuery('ip', 'string', ''));
            $db = $this->db();
            if ($db === null || $ip === '') return ["ip"=>$ip,"rows"=>[],"total"=>0,"limit"=>$limit,"offset"=>$offset,"through"=>$through];
            $count = $db->prepare("SELECT COUNT(*) total,COALESCE(MAX(rowid),0) latest FROM events WHERE ip=:ip" . ($through > 0 ? " AND rowid<=:through" : ""));
            $count->bindValue(':ip', $ip, SQLITE3_TEXT);
            if ($through > 0) $count->bindValue(':through', $through, SQLITE3_INTEGER);
            $summary = $count->execute()->fetchArray(SQLITE3_ASSOC);
            $total = (int)$summary['total'];
            if ($through === 0) $through = (int)$summary['latest'];
            $eventHits = $this->eventHits($db);
            $s = $db->prepare("SELECT ts,source,reason,{$eventHits} AS hits FROM events WHERE ip=:ip AND rowid<=:through ORDER BY ts DESC,rowid DESC LIMIT :limit OFFSET :offset");
            $s->bindValue(":ip", $ip, SQLITE3_TEXT);
            $s->bindValue(':through', $through, SQLITE3_INTEGER);
            $s->bindValue(':limit', $limit, SQLITE3_INTEGER);
            $s->bindValue(':offset', $offset, SQLITE3_INTEGER);
            $r = $s->execute(); $rows = [];
            while ($x = $r->fetchArray(SQLITE3_ASSOC)) $rows[] = $x;
            $db->close();
            return ["ip"=>$ip,"rows"=>$rows,"total"=>$total,"limit"=>$limit,"offset"=>$offset,"through"=>$through];
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
