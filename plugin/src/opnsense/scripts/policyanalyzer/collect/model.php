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
 * Cron jobs of the local collectors (collect/), changed only through the core model OPNsense\Cron\Cron (same
 * validation and config handling as System > Settings > Cron). Applying is done by the caller
 * ("configctl cron restart"). Command, parameters, schedule and description are fixed here, never taken from
 * the caller.
 *
 *   model.php cron_set <flows|health|config>    create, or reset to the fixed schedule and enable
 *   model.php cron_del <flows|health|config>    delete the job of that kind
 *
 * Output: one JSON document {"status": "ok"|"error", "uuid", "created", "changed", "deleted", "message"}.
 */

require_once('legacy_bindings.inc');

use OPNsense\Core\Config;
use OPNsense\Cron\Cron;

const CRON_ORIGIN = 'PolicyAnalyzer';
/* the core cron model only accepts a configd action ("pa_collect run") as command; the kind goes in parameters */
const CRON_COMMAND = 'pa_collect run';
const JOBS = [
    'flows' => ['*/5', '*', 'Policy Analyzer: local collector, firewall blocks and DNS queries (every 5 minutes)'],
    'health' => ['7', '*', 'Policy Analyzer: local collector, firewall health (hourly)'],
    'config' => ['3', '*', 'Policy Analyzer: local collector, config.xml history (hourly)'],
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

function find_job($mdl, $kind)
{
    foreach ($mdl->jobs->job->iterateItems() as $uuid => $node) {
        if ((string)$node->command === CRON_COMMAND && trim((string)$node->parameters) === $kind) {
            return [$uuid, $node];
        }
    }
    return [null, null];
}

function save($mdl, $node = null)
{
    if ($node !== null) {
        $prefix = $node->__reference . '.';
        $errors = [];
        foreach ($mdl->performValidation() as $msg) {
            if (strpos($msg->getField(), $prefix) === 0) {
                $errors[] = substr($msg->getField(), strlen($prefix)) . ': ' . $msg->getMessage();
            }
        }
        if (!empty($errors)) {
            fail(implode('; ', $errors));
        }
    }
    $mdl->serializeToConfig(false, true);
    Config::getInstance()->save();
}

$cmd = $argv[1] ?? '';
$kind = $argv[2] ?? '';
Config::getInstance()->lock();
if (!isset(JOBS[$kind])) {
    fail('unknown job kind');
}
[$minutes, $hours, $descr] = JOBS[$kind];
$mdl = new Cron();

switch ($cmd) {
    case 'cron_set':
        [$uuid, $node] = find_job($mdl, $kind);
        $created = false;
        if ($node === null) {
            $node = $mdl->jobs->job->Add();
            $uuid = $node->getAttributes()['uuid'];
            $created = true;
        } elseif ((string)$node->minutes === $minutes && (string)$node->hours === $hours &&
                  (string)$node->enabled === '1') {
            Config::getInstance()->unlock();
            out(['status' => 'ok', 'uuid' => $uuid, 'created' => false, 'changed' => false]);
        }
        $node->origin = CRON_ORIGIN;
        $node->enabled = '1';
        $node->minutes = $minutes;
        $node->hours = $hours;
        $node->days = '*';
        $node->months = '*';
        $node->weekdays = '*';
        $node->who = 'root';
        $node->command = CRON_COMMAND;
        $node->parameters = $kind;
        $node->description = $descr;
        save($mdl, $node);
        out(['status' => 'ok', 'uuid' => $uuid, 'created' => $created, 'changed' => true]);
        break;

    case 'cron_del':
        [$uuid, $node] = find_job($mdl, $kind);
        if ($node === null) {
            Config::getInstance()->unlock();
            out(['status' => 'ok', 'deleted' => false]);
        }
        $mdl->jobs->job->del($uuid);
        save($mdl);
        out(['status' => 'ok', 'uuid' => $uuid, 'deleted' => true]);
        break;

    default:
        fail('usage: model.php cron_set <flows|health|config> | cron_del <flows|health|config>');
}
