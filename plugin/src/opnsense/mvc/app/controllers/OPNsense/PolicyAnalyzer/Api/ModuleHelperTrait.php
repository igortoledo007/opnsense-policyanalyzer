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

namespace OPNsense\PolicyAnalyzer\Api;

/**
 * Shared by the module controllers (Reports, Vulns, Devices): "simulate, then apply" through the module's own
 * configd topic (pa_reports / pa_vulns / pa_devices), so the actions run even before ai/changes.py lists the
 * packages. The journal is the common one: the entries show up in the "Action history" tab of the Policy
 * Analyzer, and "revert" works from both places (from there once ai/changes.py EXTENSIONS lists the package,
 * see CONTRACT.md, "Change actions").
 */
trait ModuleHelperTrait
{
    /** a long token (base64url JSON payload of reports_settings) */
    public const LONG_TOKEN = '/^[A-Za-z0-9_-]{1,16384}$/';

    /**
     * @param string $topic configd topic, e.g. "pa_reports"
     * @param array $actions allowed action => max number of arguments
     * @param string $mode plan|apply
     */
    protected function moduleChange($topic, array $actions, $mode)
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        $action = (string)$this->request->getPost('action');
        if (!isset($actions[$action])) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid action.')];
        }
        $args = array_values((array)$this->request->getPost('args', null, []));
        if (count($args) > $actions[$action]) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Too many arguments.')];
        }
        foreach ($args as $arg) {
            if (!is_string($arg)) {
                return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid argument.')];
            }
            $long = $action === 'reports_settings' && preg_match(self::LONG_TOKEN, $arg);
            if (!$long && (!preg_match(self::ARG_TOKEN, $arg) || in_array('..', explode('/', $arg)))) {
                return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid argument.')];
            }
        }
        if ($action === 'revert' && !preg_match(self::JOURNAL_ID, $args[0] ?? '')) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid journal id.')];
        }
        if ($mode === 'apply') {
            $this->throwReadOnly();
        }
        return $this->configdJson($topic . ' ' . $mode, array_merge([$action], $args), $mode === 'apply' ? 600 : 120);
    }

    /** page:rows of the list endpoints */
    protected function pageToken($defaultRows = 25)
    {
        $page = max(1, (int)$this->request->get('page', 'int', 1));
        $rows = max(1, min(200, (int)$this->request->get('rows', 'int', $defaultRows)));
        return $page . ':' . $rows;
    }
}
