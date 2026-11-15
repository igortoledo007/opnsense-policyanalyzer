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
 * The cron job of the incident triage, changed only through the core model OPNsense\Cron\Cron (the same
 * validation and config handling as System: Settings: Cron). Applying is done by the caller
 * ("configctl cron restart"). The command and the description are fixed here, never taken from the caller.
 *
 *   model.php cron_add
 *   model.php cron_del <uuid>
 *
 * Output: one JSON document {"status": "ok"|"error", "uuid", "created", "deleted", "message"}.
 */

require_once('legacy_bindings.inc');

use OPNsense\Core\Config;
use OPNsense\Cron\Cron;

const CRON_COMMAND = 'pa_incidents run';
const CRON_DESCR = 'Policy Analyzer incidents (correlation every 5 minutes)';
const CRON_ORIGIN = 'PolicyAnalyzer';

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

/* validation messages of the new job only: unrelated problems of other entries never block us */
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

function valid_uuid($value)
{
    return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $value) === 1;
}

$cmd = $argv[1] ?? '';
Config::getInstance()->lock();

switch ($cmd) {
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
            fail('not the incidents job');
        }
        $mdl->jobs->job->del($uuid);
        save($mdl);
        out(['status' => 'ok', 'deleted' => true]);
        break;

    default:
        fail('usage: model.php cron_add|cron_del <uuid>');
}
