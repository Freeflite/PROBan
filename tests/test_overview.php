<?php

namespace OPNsense\Base {
    class ApiControllerBase
    {
        public $request;
    }
}

namespace OPNsense\Core {
    class Config
    {
        public static $saves = 0;

        public static function getInstance()
        {
            return new self();
        }

        public function save()
        {
            self::$saves++;
        }
    }

    class Backend
    {
        public function configdRun($command)
        {
        }
    }
}

namespace OPNsense\ProBAN {
    class General
    {
        public static $hideExpired = '0';
        public static $values = [];
        public $hide_expired;
        private $fields = [];

        public function __construct()
        {
            $this->hide_expired = self::$hideExpired;
            $this->fields = self::$values;
        }

        public function __get($name)
        {
            return $this->fields[$name] ?? '';
        }

        public function __set($name, $value)
        {
            $this->fields[$name] = $value;
        }

        public function performValidation()
        {
            return new \ArrayObject();
        }

        public function serializeToConfig()
        {
            self::$hideExpired = $this->hide_expired;
            self::$values = $this->fields;
        }
    }
}

namespace OPNsense\Firewall {
    class AliasItems
    {
        public $created;

        public function Add()
        {
            $this->created = new \stdClass();
            return $this->created;
        }
    }

    class Alias
    {
        public static $nodes = [];
        public $aliases;

        public function __construct()
        {
            $this->aliases = (object)['alias' => new AliasItems()];
        }

        public function getByName($name)
        {
            return self::$nodes[$name] ?? null;
        }

        public function serializeToConfig()
        {
            $created = $this->aliases->alias->created;
            if ($created !== null) self::$nodes[$created->name] = $created;
        }
    }

    class Plugin
    {
        public $filters = [];
        public $forwards = [];

        public function registerFilterRule($priority, $rule)
        {
            $this->filters[] = ['priority' => $priority, 'rule' => $rule];
        }

        public function registerForwardRule($priority, $rule)
        {
            $this->forwards[] = ['priority' => $priority, 'rule' => $rule];
        }
    }
}

namespace {
    function check($condition, $message)
    {
        if (!$condition) throw new \RuntimeException($message);
    }

    $root = dirname(__DIR__);
    require $root . '/src/opnsense/mvc/app/library/OPNsense/ProBAN/Helper.php';
    require $root . '/src/etc/inc/plugins.inc.d/proban.inc';
    $config = ['OPNsense' => ['proban' => ['general' => ['enabled' => '1', 'action' => 'drop']]]];
    $firewall = new \OPNsense\Firewall\Plugin();
    proban_firewall($firewall);
    check(count($firewall->filters) === 2, 'Both address families need block rules');
    foreach ($firewall->filters as $filter) {
        check($filter['priority'] === 0, 'ProBAN must precede priority-1 rules');
        check($filter['rule']['log'] === false, 'Blocked packets must not flood the live log');
        check($filter['rule']['quick'] === true && $filter['rule']['type'] === 'block', 'Blocks must remain quick');
    }
    foreach (\OPNsense\Firewall\Alias::$nodes as $alias) {
        check($alias->counters === '1', 'New aliases need address counters');
        $alias->counters = '0';
    }
    proban_firewall(new \OPNsense\Firewall\Plugin());
    check(\OPNsense\Core\Config::$saves === 4, 'Existing aliases must be upgraded');
    proban_firewall(new \OPNsense\Firewall\Plugin());
    check(\OPNsense\Core\Config::$saves === 4, 'Unchanged aliases must not rewrite configuration');

    foreach ([null, 'detect_udp', 'detect_portscan'] as $detector) {
        $udp = $detector !== null;
        $config['OPNsense']['proban']['general'] = ['enabled' => '1', 'action' => 'tarpit',
            'tarpit_ip' => '10.66.66.10', 'tarpit_ip6' => 'fd00:66::10',
            'detect_udp' => $detector === 'detect_udp' ? '1' : '0',
            'detect_portscan' => $detector === 'detect_portscan' ? '1' : '0'];
        $firewall = new \OPNsense\Firewall\Plugin();
        proban_firewall($firewall);
        check(count($firewall->forwards) === 2, 'UDP detection must retain both TCP tarpit redirects');
        check(count($firewall->filters) === ($udp ? 2 : 0), 'Enabled UDP detection needs drop rules even in tarpit mode');
        foreach ($firewall->filters as $filter) {
            check($filter['rule']['protocol'] === 'udp' && $filter['rule']['type'] === 'block', 'Additional rules must only drop UDP');
            check($filter['priority'] === 0 && $filter['rule']['quick'] && !$filter['rule']['log'], 'UDP drops must remain early, quick and quiet');
        }
    }
    $config['OPNsense']['proban']['general'] = ['enabled' => '1', 'action' => 'drop'];

    $source = file_get_contents($root . '/src/opnsense/mvc/app/controllers/OPNsense/ProBAN/Api/OverviewController.php');
    $source = str_replace('$p = "/var/log/parabolic/offenders.db";', '$p = $GLOBALS["probanTestDatabase"];', $source);
    eval(substr($source, 5));
    foreach ([false, true] as $weighted) {
        if (!is_dir(sys_get_temp_dir())) mkdir(sys_get_temp_dir(), 0700, true);
        $probanTestDatabase = tempnam(sys_get_temp_dir(), 'proban-api-');
        check($probanTestDatabase !== false, 'Temporary database must be available');
        $database = new \SQLite3($probanTestDatabase);
        $database->exec('CREATE TABLE offenders(ip TEXT,hits INT,last_seen INT,ban_secs REAL,level INT,blocked_until INT,reasons TEXT)');
        $database->exec('CREATE TABLE state(k TEXT PRIMARY KEY,v TEXT)');
        $database->exec("INSERT INTO state VALUES('counter_error','test counter warning')");
        $database->exec('CREATE TABLE events(ts INT,ip TEXT,source TEXT,reason TEXT' . ($weighted ? ',hits INT NOT NULL DEFAULT 1' : '') . ')');
        $now = time();
        $database->exec("INSERT INTO offenders VALUES('203.0.113.7',251,{$now},5000,5," . ($now + 10000) . ",'pf:250 blocked packets')");
        foreach ([1, 250] as $count) {
            $database->exec("INSERT INTO events VALUES(" . ($now - $count) . ",'203.0.113.7','pf','blocked'" . ($weighted ? ',' . $count : '') . ')');
        }
        $database->close();
        $controller = new \OPNsense\ProBAN\Api\OverviewController();
        $controller->request = new class {
            public $query = [];

            public function getQuery($name, $filter, $default)
            {
                return $this->query[$name] ?? $default;
            }
        };
        $expected = $weighted ? 251 : 2;
        $stats = $controller->statsAction();
        check($stats['events24h'] === $expected, '24-hour totals must include weighted hits and support old databases');
        check($stats['counter_error'] === 'test counter warning', 'Counter errors must reach the GUI');
        $timeline = $controller->timelineAction(60, 3600, $now + 1);
        check(array_sum(array_column($timeline['buckets'], 'c')) === $expected, 'Timeline must sum hits');
        $events = $controller->eventsAction('203.0.113.7');
        check(array_sum(array_column($events['rows'], 'hits')) === $expected, 'History must expose batch weights');
        $offenders = $controller->offendersAction();
        check((int)$offenders['rows'][0]['hits'] === 251, 'Offender hit counter must remain available');
        check((int)$offenders['rows'][0]['last_seen'] === $now, 'Latest activity must be available');

        $database = new \SQLite3($probanTestDatabase);
        $database->exec("UPDATE offenders SET reasons='firewall:TCP SYN probe to 192.0.2.1:23\npf:250 more packets blocked' WHERE ip='203.0.113.7'");
        check($controller->offendersAction()['rows'][0]['last_reason'] === 'firewall:TCP SYN probe to 192.0.2.1:23',
            'PF updates must not replace the detection reason in the overview');
        $database->exec("INSERT INTO offenders VALUES('2001:db8:bad::1',2,{$now},30,1," . ($now + 10000) . ",'probe')");
        foreach (['203.0.113.8' => $now - 60, '2001:db8:bad::2' => $now - 60, '203.0.113.9' => $now] as $address => $until) {
            $database->exec("INSERT INTO offenders VALUES('{$address}',3,{$now},0,0,{$until},'expired probe')");
        }
        $database->exec("INSERT INTO events(ts,ip,source,reason) VALUES({$now},'203.0.113.8','firewall','expired probe')");
        $database->close();
        check($controller->offendersAction()['total'] === 5, 'Expired offenders remain visible by default');
        check($controller->statsAction()['total'] === 5, 'Default offender total includes expired entries');

        \OPNsense\ProBAN\General::$hideExpired = '1';
        $offenders = $controller->offendersAction();
        check($offenders['total'] === 2 && count($offenders['rows']) === 2, 'Expired IPv4/IPv6 entries and exact-expiry boundaries must be hidden');
        check($controller->statsAction()['total'] === 2, 'Offender statistic must match the filtered overview');
        $controller->request->query = ['family' => 4];
        $offenders = $controller->offendersAction();
        check($offenders['total'] === 1 && $offenders['rows'][0]['ip'] === '203.0.113.7', 'IPv4 filter must combine with expiry filtering');
        $controller->request->query = ['family' => 6];
        $offenders = $controller->offendersAction();
        check($offenders['total'] === 1 && $offenders['rows'][0]['ip'] === '2001:db8:bad::1', 'IPv6 filter must combine with expiry filtering');
        $controller->request->query = ['sort' => 'ip', 'dir' => 1, 'limit' => 1, 'offset' => 1];
        $offenders = $controller->offendersAction();
        check($offenders['total'] === 2 && count($offenders['rows']) === 1 && $offenders['rows'][0]['ip'] === '203.0.113.7', 'Pagination and sorting must apply after expiry filtering');
        $controller->request->query = [];
        check(count($controller->eventsAction('203.0.113.8')['rows']) === 1, 'Hidden offenders must retain their history');
        check($controller->statsAction()['events24h'] === $expected + 1, 'Hiding expired entries must not discard event totals');

        $controller->request->query = [];
        $database = new \SQLite3($probanTestDatabase);
        $database->exec("UPDATE offenders SET ban_secs=30,blocked_until=" . ($now + 10000) . " WHERE ip='203.0.113.8'");
        check((int)$database->querySingle('SELECT COUNT(*) FROM offenders') === 5, 'Filtering must not delete offender records');
        $database->close();
        check($controller->offendersAction()['total'] === 3, 'Renewed offenders must reappear automatically');
        \OPNsense\ProBAN\General::$hideExpired = '0';
        check($controller->offendersAction()['total'] === 5, 'Disabling the setting must show all offenders again');

          foreach (['203.0.113.7' => 1, ' 203.0.113.7 ' => 1, '203.0.113.' => 3,
                '2001:DB8:BAD::1' => 1, '%' => 0, '_' => 0, "' OR 1=1 --" => 0] as $search => $matches) {
            $controller->request->query = ['search' => $search];
            $offenders = $controller->offendersAction();
            check($offenders['total'] === $matches && count($offenders['rows']) === $matches,
                'IP search must be literal, case-insensitive, trimmed and safely bound: ' . $search);
          }
          $controller->request->query = ['search' => '203.0.113.', 'sort' => 'ip', 'dir' => 1, 'limit' => 1, 'offset' => 1];
          $offenders = $controller->offendersAction();
          check($offenders['total'] === 3 && $offenders['rows'][0]['ip'] === '203.0.113.8', 'Search pagination must use the matching row count');
          $controller->request->query = ['search' => '203.0.113.', 'family' => 6];
          check($controller->offendersAction()['total'] === 0, 'Search must combine with address-family filtering');
          $controller->request->query = ['search' => '203.0.113.'];
          \OPNsense\ProBAN\General::$hideExpired = '1';
          check($controller->offendersAction()['total'] === 2, 'Search must respect hidden expired offenders');
          check($controller->statsAction()['total'] === 3, 'Search must not change the dashboard-wide offender total');
          \OPNsense\ProBAN\General::$hideExpired = '0';
          $controller->request->query = [];

        $database = new \SQLite3($probanTestDatabase);
        $insert = $database->prepare("INSERT INTO events(ts,ip,source,reason) VALUES(:ts,'203.0.113.7','test',:reason)");
        for ($entry = 0; $entry < 205; $entry++) {
            $insert->bindValue(':ts', $now - 300 - intdiv($entry, 3), SQLITE3_INTEGER);
            $insert->bindValue(':reason', 'page event ' . $entry, SQLITE3_TEXT);
            $insert->execute();
        }
        $database->exec("INSERT INTO events(ts,ip,source,reason) VALUES({$now},'2001:db8:bad::/64','pf','subnet total')");
        $database->close();
        $firstPage = $controller->eventsAction('203.0.113.7');
        check($firstPage['total'] === 207 && count($firstPage['rows']) === 100, 'History must expose totals beyond the former 100-event limit');
        check($firstPage['rows'][2]['reason'] === 'page event 2', 'Equal event timestamps need stable newest-row-first ordering');
        $history = [];
        foreach ([0, 100, 200] as $offset) {
            $controller->request->query = ['offset' => $offset, 'through' => $firstPage['through']];
            $page = $controller->eventsAction('203.0.113.7');
            check($page['total'] === 207 && $page['offset'] === $offset, 'Every history page needs consistent metadata');
            $history = array_merge($history, $page['rows']);
        }
        $identities = array_map(function ($event) { return $event['ts'] . ':' . $event['reason']; }, $history);
        check(count($history) === 207 && count(array_unique($identities)) === 207, 'History pages must not omit or repeat entries');
        $database = new \SQLite3($probanTestDatabase);
        $database->exec("INSERT INTO events(ts,ip,source,reason) VALUES(" . ($now + 1) . ",'203.0.113.7','pf','new arrival')");
        $database->close();
        $controller->request->query = ['through' => $firstPage['through']];
        $snapshot = $controller->eventsAction('203.0.113.7');
        check($snapshot['total'] === 207 && $snapshot['rows'] === $firstPage['rows'], 'New traffic must not shift an open history snapshot');
        $controller->request->query = ['limit' => 10000, 'offset' => -5];
        $page = $controller->eventsAction('203.0.113.7');
        check($page['limit'] === 500 && $page['offset'] === 0 && $page['total'] === 208, 'History limits must be bounded and a new view must see new events');
        $controller->request->query = ['limit' => 0];
        check(count($controller->eventsAction('203.0.113.7')['rows']) === 1, 'Zero must not request an unbounded history');
        $controller->request->query = ['ip' => '2001:db8:bad::/64'];
        $subnet = $controller->eventsAction();
        check($subnet['ip'] === '2001:db8:bad::/64' && $subnet['total'] === 1 && $subnet['rows'][0]['reason'] === 'subnet total', 'Query-based addresses must preserve IPv6 subnet prefixes');
        $controller->request->query = ['ip' => "' OR 1=1 --"];
        check($controller->eventsAction()['total'] === 0, 'History addresses must remain safely bound');
        $controller->request->query = [];
        unlink($probanTestDatabase);
    }

    require $root . '/src/opnsense/mvc/app/controllers/OPNsense/ProBAN/Api/SettingsController.php';
    $settings = new \OPNsense\ProBAN\Api\SettingsController();
    $settings->request = new class {
        public $post = [];

        public function isPost()
        {
            return true;
        }

        public function getPost($name, $filter = null, $default = null)
        {
            return $this->post[$name] ?? $default;
        }
    };
    check($settings->getAction()['hide_expired'] === 0, 'Settings must expose the default-off preference');
    foreach ([1, null, 0] as $choice) {
        $settings->request->post = $choice === null ? [] : ['hide_expired' => $choice];
        check($settings->setAction()['status'] === 'ok', 'Settings save must accept the expiry preference');
        check($settings->getAction()['hide_expired'] === ($choice ?? 1), 'Preference must survive a new model instance and omitted values');
    }
    $defaults = ['detect_syn' => 1, 'detect_udp' => 0, 'detect_tcp_scan' => 0,
                 'detect_tcp_invalid' => 0, 'detect_portscan' => 0, 'portscan_threshold' => 10, 'portscan_window' => 60,
                 'detect_v6_rotation' => 0, 'v6_rotation_sources' => 8, 'v6_rotation_hits' => 40,
                 'v6_rotation_window' => 300, 'v6_rotation_secs' => 600,
                 'scan_threshold' => 5, 'scan_window' => 60, 'suricata_priority' => 0,
                 'suricata_priority_severity' => 1, 'suricata_priority_secs' => 1800, 'suricata_priority_sids' => ''];
    $actual = $settings->getAction();
    foreach ($defaults as $field => $value) {
        check(($actual[$field] ?? null) === $value, 'Settings must expose the scan default: ' . $field);
    }
    $custom = ['detect_syn' => 0, 'detect_udp' => 1, 'detect_tcp_scan' => 1,
               'detect_tcp_invalid' => 1, 'detect_portscan' => 1, 'portscan_threshold' => 20, 'portscan_window' => 90,
               'detect_v6_rotation' => 1, 'v6_rotation_sources' => 12, 'v6_rotation_hits' => 80,
               'v6_rotation_window' => 600, 'v6_rotation_secs' => 1200,
               'scan_threshold' => 12, 'scan_window' => 90, 'suricata_priority' => 1,
               'suricata_priority_severity' => 2, 'suricata_priority_secs' => 3600, 'suricata_priority_sids' => '1001,1002'];
    foreach ([$custom, [], $defaults] as $posted) {
        $settings->request->post = $posted;
        check($settings->setAction()['status'] === 'ok', 'Settings must accept scan preferences');
        $actual = $settings->getAction();
        foreach (($posted ?: $custom) as $field => $value) {
            check($actual[$field] === $value, 'Scan preference must survive saving and omitted values: ' . $field);
        }
    }
    $settings->request->post = ['v6_rotation_sources' => 12, 'v6_rotation_hits' => 1,
                                'v6_rotation_window' => 1, 'v6_rotation_secs' => 1];
    check($settings->setAction()['status'] === 'ok', 'Settings must clamp unsafe low IPv6 correlation values');
    $actual = $settings->getAction();
    check($actual['v6_rotation_hits'] === 12 && $actual['v6_rotation_window'] === 10 && $actual['v6_rotation_secs'] === 60,
        'IPv6 correlation requires at least one probe per source, a bounded window and a minimum ban');
    echo "PASS: quiet rules, alias counters, weighted/legacy API, expired-offender filtering and settings round-trip\n";
}
