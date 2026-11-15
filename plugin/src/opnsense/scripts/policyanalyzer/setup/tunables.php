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
 * System tunables (System: Settings: Tunables) through the core model OPNsense\Core\Tunables
 * (//sysctl/item in config.xml), the same way the GUI and the core scripts (auth/add_user.php) do.
 * Applying (regenerating /boot/loader.conf) is done by the caller with
 * "configctl service restart login" + "configctl service restart sysctl", like the Tunables page.
 *
 *   tunables.php get <name>                    {"exists", "value", "descr"}
 *   tunables.php set <name> <value> <descr>    add or update the user entry
 *   tunables.php del <name>                    remove the user entry
 *
 * Only an allow-listed tunable can be changed by this plugin.
 */

require_once('legacy_bindings.inc');

use OPNsense\Core\Config;
use OPNsense\Core\Tunables;

const ALLOWED = ['kern.racct.enable'];

function out($data, $code = 0)
{
    echo json_encode($data) . "\n";
    exit($code);
}

function find_item($mdl, $name)
{
    foreach ($mdl->item->iterateItems() as $uuid => $node) {
        if ((string)$node->tunable === $name) {
            return [$uuid, $node];
        }
    }
    return [null, null];
}

$cmd = $argv[1] ?? '';
$name = $argv[2] ?? '';
if (!in_array($name, ALLOWED, true)) {
    out(['status' => 'error', 'message' => 'tunable not allowed'], 1);
}

if ($cmd === 'get') {
    [$uuid, $node] = find_item(new Tunables(), $name);
    out(['status' => 'ok', 'exists' => $node !== null && (string)$node->value !== '',
         'value' => $node !== null ? (string)$node->value : null,
         'descr' => $node !== null ? (string)$node->descr : null]);
}

if ($cmd !== 'set' && $cmd !== 'del') {
    out(['status' => 'error', 'message' => 'usage: tunables.php get|set|del <name> [value descr]'], 1);
}

$value = $argv[3] ?? '';
$descr = $argv[4] ?? '';
if ($cmd === 'set' && !preg_match('/^[0-9A-Za-z._-]{1,32}$/', $value)) {
    out(['status' => 'error', 'message' => 'invalid value'], 1);
}
if (!preg_match('/^[\x20-\x7e]{0,200}$/', $descr)) {
    out(['status' => 'error', 'message' => 'invalid description'], 1);
}

Config::getInstance()->lock();
$mdl = new Tunables();
[$uuid, $node] = find_item($mdl, $name);
if ($cmd === 'del') {
    if ($uuid !== null) {
        $mdl->item->del($uuid);
    }
} else {
    if ($node === null) {
        $node = $mdl->item->Add();
        $node->tunable = $name;
    }
    $node->value = $value;
    $node->descr = $descr;
}
$errors = [];
foreach ($mdl->performValidation() as $msg) {
    $errors[] = $msg->getField() . ': ' . $msg->getMessage();
}
if (!empty($errors)) {
    Config::getInstance()->unlock();
    out(['status' => 'error', 'message' => implode('; ', $errors)], 1);
}
if ($mdl->serializeToConfig(false, true)) {
    Config::getInstance()->save();
} else {
    Config::getInstance()->unlock();
}
out(['status' => 'ok']);
