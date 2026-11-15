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

use OPNsense\Core\Backend;

/**
 * Shared helpers for the Policy Analyzer API controllers (used as a trait so both plain and
 * model bound controllers can share them).
 */
trait ApiHelperTrait
{
    /** finding ids are short hex digests (see CONTRACT.md, "Finding ids") */
    public const FINDING_ID = '/^[0-9a-f]{6,64}$/';
    /** journal ids written by scripts/policyanalyzer/ai/journal.py */
    public const JOURNAL_ID = '/^[0-9]{8}T[0-9]{6}-[0-9a-f]{6}$/';
    /** change action names registered in scripts/policyanalyzer/ai/changes.py (and extensions) */
    public const ACTION_NAME = '/^[a-z][a-z0-9_]{0,63}$/';
    /**
     * a simple argument token, no whitespace or quotes: paths, model names (qwen2.5:3b), flags (+large,
     * keep_models=no, force), limits (2-3/2/8192/20), journal ids
     */
    public const ARG_TOKEN = '/^[A-Za-z0-9\/_.:@+=-]{0,255}$/';

    /**
     * run a configd action and decode its JSON answer
     * @param string $action configd action, e.g. "policyanalyzer findings"
     * @param array $params simple parameters, already validated by the caller
     * @param int $timeout seconds
     * @return array decoded answer or a status=error structure
     */
    protected function configdJson($action, $params = [], $timeout = 120)
    {
        $backend = new Backend();
        if (empty($params)) {
            $response = $backend->configdRun($action, false, $timeout);
        } else {
            $response = $backend->configdpRun($action, $params, false, $timeout);
        }
        $data = json_decode(trim((string)$response), true);
        if (!is_array($data)) {
            return [
                'status' => 'error',
                'message' => empty(trim((string)$response)) ?
                    \OPNsense\PolicyAnalyzer\L10n::t('No answer from the backend (timeout or script error), see the system log.') :
                    \OPNsense\PolicyAnalyzer\L10n::t('Unexpected answer from the backend.'),
            ];
        }
        return $data;
    }

    /**
     * journal a settings change: "snapshot" before saving, "record" after (returns the journal id)
     */
    protected function settingsJournal($step, $extra = [])
    {
        $data = $this->configdJson('policyanalyzer settings_journal', array_merge([$step], $extra), 30);
        return $data['journal_id'] ?? null;
    }

    /**
     * @return \OPNsense\PolicyAnalyzer\PolicyAnalyzer
     */
    protected function settings()
    {
        return new \OPNsense\PolicyAnalyzer\PolicyAnalyzer();
    }

    /** per scenario AI routing written by the change action ai_routing (scripts/policyanalyzer/ai/scenarios.py) */
    public const AI_ROUTING = '/var/db/policyanalyzer/ai-routing.json';

    /**
     * seconds to wait for the AI backend: the per scenario value computed by the backend when the scenario has
     * its own routing (timeout, correction attempt and a synchronous fallback included), else the setting, or
     * the provider default when empty
     * @param string|null $scenario scenario id of the catalog (explain_finding, console_ask, ...)
     */
    protected function aiTimeout($scenario = null)
    {
        if ($scenario !== null && is_readable(self::AI_ROUTING)) {
            $routing = json_decode((string)@file_get_contents(self::AI_ROUTING), true);
            $value = (int)($routing['effective'][$scenario]['php_timeout'] ?? 0);
            if ($value > 0) {
                /* the script adds its own margins: the request must outlive the longest synchronous route */
                return min($value, 3600);
            }
        }
        $mdl = $this->settings();
        $timeout = (int)(string)$mdl->ai->timeout;
        if ($timeout <= 0) {
            // local Ollama on this firewall runs on a few CPU cores: a finding takes 1-3 minutes (prompt + answer)
            $provider = (string)$mdl->ai->provider;
            $local = $provider == 'ollama' && (string)$mdl->ollama->location != 'lan';
            /* Claude Code (LAN): the bridge gets 300 s, the script waits 15 s more and explain adds 30 s on top */
            $defaults = ['claude' => 180, 'claudecode' => 300];
            $timeout = $defaults[$provider] ?? ($local ? 360 : 120);
        }
        return $timeout;
    }

    /**
     * AI language: explicit setting or the language of the current GUI session
     */
    protected function aiLanguage()
    {
        $lang = (string)$this->settings()->ai->language;
        if ($lang == '' || $lang == 'auto') {
            $lang = $this->langcode;
        }
        return preg_match('/^[a-z]{2,3}(_[A-Z]{2})?$/', $lang) ? $lang : 'en_US';
    }
}
