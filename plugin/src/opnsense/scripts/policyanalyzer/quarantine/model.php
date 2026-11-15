<?php

/*
 * Copyright (C) 2026 Igor Toledo <contato@igor.eti.br>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * The firewall objects of the quarantine, changed only through the core models (the same validation and
 * config handling as the GUI): OPNsense\Firewall\Alias, OPNsense\Firewall\Filter (Firewall: Rules /
 * Automation) and OPNsense\Cron\Cron. Applying is done by the caller ("configctl filter reload",
 * "configctl cron restart"). Names, descriptions and the command are fixed here, never taken from the caller.
 *
 *   model.php alias_add <pa_quarantine|pa_never_block> [base64 newline separated content]
 *   model.php alias_del <uuid>
 *   model.php alias_entry <pa_never_block> <add|del> <address or network>
 *   model.php rule_add <sequence> <interface,interface,...> [0|1]    the last argument: enabled (default 1)
 *   model.php rule_del <uuid>
 *   model.php rule_enable <uuid> <0|1>
 *   model.php rule_log <uuid> <0|1>          logging of a PASS rule (the WireGuard rule of the guard), never others
 *   model.php cron_add
 *   model.php cron_del <uuid>
 *
 * Output: one JSON document {"status": "ok"|"error", "uuid", "created", "message"}.
 */

require_once('legacy_bindings.inc');

use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;
use OPNsense\Firewall\Filter;
use OPNsense\Cron\Cron;

const RULE_DESCR = 'Max Cyber IA';
const CRON_COMMAND = 'policyanalyzer quarantine_run';
const CRON_DESCR = 'Policy Analyzer quarantine (Max Cyber IA)';
const CRON_ORIGIN = 'PolicyAnalyzer';
const ALIASES = [
    'pa_quarantine' => ['type' => 'external', 'counters' => '1',
                        'description' => 'Max Cyber IA quarantine (pf table managed by the Policy Analyzer)'],
    'pa_never_block' => ['type' => 'network', 'counters' => '0',
                         'description' => 'Max Cyber IA: never put in quarantine (edited by the owner)'],
];

function out($data, $code = 0)
{
    echo json_encode($data) . "\n";
    exit($code);
}

function fail($message)
{
    Config::getInstance()->unlock();
    out(['status' => 'error', 'message' => $message], 1);
}

/* validation messages of one node only: unrelated problems of other entries never block us */
function node_errors($mdl, $node)
{
    $prefix = $node->__reference . '.';
    $errors = [];
    foreach ($mdl->performValidation() as $msg) {
        if (strpos($msg->getField(), $prefix) === 0) {
            $errors[] = substr($msg->getField(), strlen($prefix)) . ': ' . $msg->getMessage();
        }
    }
    return $errors;
}

function save($mdl, $node = null)
{
    if ($node !== null) {
        $errors = node_errors($mdl, $node);
        if (!empty($errors)) {
            fail(implode('; ', $errors));
        }
    }
    $mdl->serializeToConfig(false, true);
    Config::getInstance()->save();
}

function find_alias($mdl, $name)
{
    foreach ($mdl->aliases->alias->iterateItems() as $uuid => $node) {
        if ((string)$node->name === $name) {
            return [$uuid, $node];
        }
    }
    return [null, null];
}

function valid_uuid($value)
{
    return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $value) === 1;
}

$cmd = $argv[1] ?? '';
Config::getInstance()->lock();

switch ($cmd) {
    case 'alias_add':
        $name = $argv[2] ?? '';
        if (!isset(ALIASES[$name])) {
            fail('alias not allowed');
        }
        $content = '';
        if (isset($argv[3]) && $argv[3] !== '') {
            $decoded = base64_decode($argv[3], true);
            if ($decoded === false || !preg_match('/^[0-9a-fA-F:.\/\n]*$/', $decoded)) {
                fail('invalid content');
            }
            $content = trim($decoded);
        }
        $mdl = new Alias();
        [$uuid, $node] = find_alias($mdl, $name);
        if ($node !== null) {
            Config::getInstance()->unlock();
            out(['status' => 'ok', 'uuid' => $uuid, 'created' => false]);
        }
        $node = $mdl->aliases->alias->Add();
        $node->enabled = '1';
        $node->name = $name;
        $node->type = ALIASES[$name]['type'];
        $node->counters = ALIASES[$name]['counters'];
        $node->content = $content;
        $node->description = ALIASES[$name]['description'];
        save($mdl, $node);
        out(['status' => 'ok', 'uuid' => $node->getAttributes()['uuid'], 'created' => true]);
        break;

    case 'alias_del':
        $uuid = $argv[2] ?? '';
        $mdl = new Alias();
        $node = valid_uuid($uuid) ? $mdl->getNodeByReference('aliases.alias.' . $uuid) : null;
        if ($node === null) {
            Config::getInstance()->unlock();
            out(['status' => 'ok', 'deleted' => false]);
        }
        if (!isset(ALIASES[(string)$node->name])) {
            fail('alias not allowed');
        }
        $mdl->aliases->alias->del($uuid);
        save($mdl);
        out(['status' => 'ok', 'deleted' => true]);
        break;

    case 'alias_entry':
        $name = $argv[2] ?? '';
        $op = $argv[3] ?? '';
        $value = $argv[4] ?? '';
        if ($name !== 'pa_never_block' || !in_array($op, ['add', 'del'], true)) {
            fail('not allowed');
        }
        $parts = explode('/', $value, 2);
        if (filter_var($parts[0], FILTER_VALIDATE_IP) === false ||
            (isset($parts[1]) && !preg_match('/^[0-9]{1,3}$/', $parts[1]))) {
            fail('invalid address');
        }
        $mdl = new Alias();
        [$uuid, $node] = find_alias($mdl, $name);
        if ($node === null) {
            fail('alias pa_never_block does not exist');
        }
        $items = array_values(array_filter(array_map('trim', explode("\n", (string)$node->content)), 'strlen'));
        $had = in_array($value, $items, true);
        if ($op === 'add' && !$had) {
            $items[] = $value;
        } elseif ($op === 'del' && $had) {
            $items = array_values(array_diff($items, [$value]));
        } else {
            Config::getInstance()->unlock();
            out(['status' => 'ok', 'changed' => false]);
        }
        $node->content = implode("\n", $items);
        save($mdl, $node);
        out(['status' => 'ok', 'changed' => true]);
        break;

    case 'rule_add':
        $sequence = $argv[2] ?? '';
        $ifaces = $argv[3] ?? '';
        $enabled = ($argv[4] ?? '1') === '0' ? '0' : '1';
        if (!preg_match('/^[0-9]{1,6}$/', $sequence) || !preg_match('/^[a-z0-9_]+(,[a-z0-9_]+)*$/', $ifaces)) {
            fail('invalid arguments');
        }
        $mdl = new Filter();
        foreach ($mdl->rules->rule->iterateItems() as $uuid => $node) {
            if ((string)$node->description === RULE_DESCR) {
                Config::getInstance()->unlock();
                out(['status' => 'ok', 'uuid' => $uuid, 'created' => false]);
            }
        }
        $node = $mdl->rules->rule->Add();
        $node->enabled = $enabled;
        $node->sequence = $sequence;
        $node->action = 'block';
        $node->quick = '1';
        $node->interface = $ifaces;
        $node->direction = 'in';
        $node->ipprotocol = 'inet46';
        $node->protocol = 'any';
        $node->source_net = 'pa_quarantine';
        $node->destination_net = 'any';
        $node->log = '1';
        $node->description = RULE_DESCR;
        save($mdl, $node);
        out(['status' => 'ok', 'uuid' => $node->getAttributes()['uuid'], 'created' => true]);
        break;

    case 'rule_del':
    case 'rule_enable':
        $uuid = $argv[2] ?? '';
        $mdl = new Filter();
        $node = valid_uuid($uuid) ? $mdl->getNodeByReference('rules.rule.' . $uuid) : null;
        if ($node === null) {
            Config::getInstance()->unlock();
            out(['status' => 'ok', 'changed' => false, 'missing' => true]);
        }
        if ((string)$node->description !== RULE_DESCR) {
            fail('not the quarantine rule');
        }
        if ($cmd === 'rule_del') {
            $mdl->rules->rule->del($uuid);
            save($mdl);
        } else {
            $value = ($argv[3] ?? '') === '1' ? '1' : '0';
            if ((string)$node->enabled === $value) {
                Config::getInstance()->unlock();
                out(['status' => 'ok', 'changed' => false]);
            }
            $node->enabled = $value;
            save($mdl, $node);
        }
        out(['status' => 'ok', 'changed' => true]);
        break;

    case 'rule_log':
        $uuid = $argv[2] ?? '';
        $value = ($argv[3] ?? '') === '1' ? '1' : '0';
        $mdl = new Filter();
        $node = valid_uuid($uuid) ? $mdl->getNodeByReference('rules.rule.' . $uuid) : null;
        if ($node === null) {
            fail('rule not found');
        }
        if ((string)$node->action !== 'pass' || (string)$node->description === RULE_DESCR) {
            fail('only the logging of a pass rule can be changed');
        }
        if ((string)$node->log === $value) {
            Config::getInstance()->unlock();
            out(['status' => 'ok', 'changed' => false]);
        }
        $node->log = $value;
        save($mdl, $node);
        out(['status' => 'ok', 'changed' => true]);
        break;

    case 'cron_add':
        $mdl = new Cron();
        foreach ($mdl->jobs->job->iterateItems() as $uuid => $node) {
            if ((string)$node->command === CRON_COMMAND) {
                Config::getInstance()->unlock();
                out(['status' => 'ok', 'uuid' => $uuid, 'created' => false]);
            }
        }
        $node = $mdl->jobs->job->Add();
        $node->origin = CRON_ORIGIN;
        $node->enabled = '1';
        $node->minutes = '*/5';
        $node->hours = '*';
        $node->days = '*';
        $node->months = '*';
        $node->weekdays = '*';
        $node->who = 'root';
        $node->command = CRON_COMMAND;
        $node->description = CRON_DESCR;
        save($mdl, $node);
        out(['status' => 'ok', 'uuid' => $node->getAttributes()['uuid'], 'created' => true]);
        break;

    case 'cron_del':
        $uuid = $argv[2] ?? '';
        $mdl = new Cron();
        $node = valid_uuid($uuid) ? $mdl->getNodeByReference('jobs.job.' . $uuid) : null;
        if ($node === null) {
            Config::getInstance()->unlock();
            out(['status' => 'ok', 'deleted' => false]);
        }
        if ((string)$node->command !== CRON_COMMAND) {
            fail('not the quarantine job');
        }
        $mdl->jobs->job->del($uuid);
        save($mdl);
        out(['status' => 'ok', 'deleted' => true]);
        break;

    default:
        fail('usage: model.php alias_add|alias_del|alias_entry|rule_add|rule_del|rule_enable|rule_log|cron_add|cron_del ...');
}
