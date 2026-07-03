<?php

/*
 * ProBAN progressive-ban plugin hooks.
 *
 *  - proban_services():  registers the engine as a supervised service (configd -> rc.d).
 *  - proban_firewall():  owns the pf integration. External aliases populated by the
 *                        engine, plus the rules that act on them, applied IDENTICALLY
 *                        to IPv4 and IPv6:
 *                          parabolic_block[6] -> block (drop mode) or rdr+pass (tarpit/honeypot)
 *                          parabolic_drop[6]  -> block (post-max "blackhole" set; tarpit mode only)
 *                        IPv6 gets the tarpit/honeypot treatment only when a private v6
 *                        target is configured; otherwise it stays block-only. Every
 *                        redirect is reflection-locked to a private/reserved target, so
 *                        it can never be turned into an outbound reflection tool.
 */

use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;
use OPNsense\Firewall\Plugin;
use OPNsense\ProBAN\Helper;

function proban_add_alias_if_not_exist($name, $descr, $proto = 'IPv4')
{
    $model = new Alias();
    if ($model->getByName($name) != null) {
        return;
    }
    $alias = $model->aliases->alias->Add();
    $alias->name = $name;
    $alias->description = $descr;
    $alias->proto = $proto;
    $alias->type = 'external';
    $model->serializeToConfig();
    Config::getInstance()->save();
}

// Register the rdr+pass rules that send an offender table into the tarpit/honeypot,
// for one address family. Shared by v4 and v6 so the two can't drift.
function proban_register_tarpit(Plugin $fw, $ipprotocol, $from_alias, $target, array $ports)
{
    $base = array(
        'interface'  => 'wan',
        'ipprotocol' => $ipprotocol,
        'protocol'   => 'tcp',
        'from'       => $from_alias,
        'to'         => '(self)',
        'target'     => $target,
        'pass'       => true,
        'descr'      => 'ProBAN tarpit/honeypot redirect (' . $ipprotocol . ')',
    );
    if (count($ports) === 1) {
        // tarpit: collapse every probe (any port) onto the single pit port
        $base['localport'] = (string)$ports[0];
        $fw->registerForwardRule(1, $base);
    } elseif (count($ports) === 0) {
        // catch-all honeypot: redirect every port, destination port preserved
        $fw->registerForwardRule(1, $base);
    } else {
        // honeypot: redirect ONLY the listed ports, each preserved. One rule per port
        // avoids pf list-syntax ambiguity.
        foreach ($ports as $p) {
            $rule = $base;
            $rule['to_port'] = (string)$p;
            $fw->registerForwardRule(1, $rule);
        }
    }
}

function proban_register_block(Plugin $fw, $ipprotocol, $from_alias, $descr)
{
    $fw->registerFilterRule(1, array(
        'ipprotocol' => $ipprotocol,
        'descr'      => $descr,
        'from'       => $from_alias,
        'direction'  => 'in',
        'type'       => 'block',
        'quick'      => true,
    ));
}

// Apply ProBAN's rules for a single address family: rdr+pass into the tarpit (plus the
// post-max blackhole drop) when a private target is set, otherwise a plain block.
function proban_apply_family(Plugin $fw, $ipprotocol, $proto, $block_alias, $block_descr,
                             $drop_alias, $drop_descr, $tarpit_ok, $target, array $ports, $blackhole)
{
    proban_add_alias_if_not_exist($block_alias, $block_descr . ' (populated by the engine)', $proto);
    if ($tarpit_ok) {
        proban_register_tarpit($fw, $ipprotocol, '<' . $block_alias . '>', $target, $ports);
        if ($blackhole) {
            proban_add_alias_if_not_exist($drop_alias, $drop_descr . ' (populated by the engine)', $proto);
            proban_register_block($fw, $ipprotocol, '<' . $drop_alias . '>', $drop_descr);
        }
    } else {
        proban_register_block($fw, $ipprotocol, '<' . $block_alias . '>', $block_descr);
    }
}

function proban_firewall(Plugin $fw)
{
    global $config;

    $general = $config['OPNsense']['proban']['general'] ?? null;
    if ($general === null) {
        return;
    }

    $enabled = isset($general['enabled']) && $general['enabled'] == '1';
    if (!$enabled) {
        return;
    }

    $dry_run = isset($general['dry_run']) && $general['dry_run'] == '1';
    $action = $general['action'] ?? 'drop';
    $ports = Helper::parsePorts($general['tarpit_ports'] ?? '');
    $blackhole = (($general['post_max_action'] ?? 'hold') === 'blackhole');
    $can_tarpit = (!$dry_run && $action === 'tarpit');

    // IPv4
    $tarpit_ip = $general['tarpit_ip'] ?? '';
    proban_apply_family(
        $fw, 'inet', 'IPv4',
        'parabolic_block', 'ProBAN block',
        'parabolic_drop', 'ProBAN blackhole (post-max drop)',
        $can_tarpit && Helper::isPrivateTarget($tarpit_ip), $tarpit_ip, $ports, $blackhole
    );

    // IPv6 -- identical treatment; tarpit/honeypot only when a private v6 target is set.
    $tarpit_ip6 = $general['tarpit_ip6'] ?? '';
    proban_apply_family(
        $fw, 'inet6', 'IPv6',
        'parabolic_block6', 'ProBAN block (IPv6)',
        'parabolic_drop6', 'ProBAN blackhole IPv6 (post-max drop)',
        $can_tarpit && Helper::isPrivateTarget($tarpit_ip6), $tarpit_ip6, $ports, $blackhole
    );
}

function proban_services()
{
    $services = array();
    $services[] = array(
        'description' => 'ProBAN progressive-ban engine',
        'configd' => array(
            'restart' => array('proban restart'),
            'start'   => array('proban start'),
            'stop'    => array('proban stop'),
        ),
        'pidfile' => '/var/run/proban.pid',
        'name' => 'proban',
    );

    return $services;
}
