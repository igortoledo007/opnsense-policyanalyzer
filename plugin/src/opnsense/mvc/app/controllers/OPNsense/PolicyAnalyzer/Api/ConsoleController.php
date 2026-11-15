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

use OPNsense\Base\ApiControllerBase;

/**
 * AI Console (read only): natural language questions about the firewall and "Explain this" for filter log
 * events, rules and Suricata alerts, plus the read-only viewers those buttons sit on.
 *
 * Every action calls configd "pa_console <action>" (scripts/policyanalyzer/console/ask.py). Free text (the
 * question, earlier turns) never travels as a configd argument: it goes as one base64 JSON token, built here
 * after validation, and the whole configd message stays below its 4 KiB limit. Nothing here changes the
 * configuration; an answer may contain a proposal, as text only.
 */
class ConsoleController extends ApiControllerBase
{
    use ApiHelperTrait;

    /** JSON budget of one request; base64 grows it by 4/3 and configd reads at most 4096 bytes */
    private const MAX_PAYLOAD = 2800;
    private const MAX_QUESTION = 600;
    private const MAX_HISTORY = 3;
    private const MAX_HISTORY_Q = 300;
    private const MAX_HISTORY_A = 900;
    private const LANG_CHOICES = ['auto', 'pt_BR', 'en_US'];

    /**
     * single line text without control characters, cut to $max characters
     */
    private function cleanText($value, $max)
    {
        $text = preg_replace('/[\x00-\x08\x0b-\x1f\x7f]+/u', ' ', (string)$value);
        $text = trim(preg_replace('/[ \t]{2,}/u', ' ', $text ?? ''));
        return mb_substr($text, 0, $max, 'UTF-8');
    }

    private function payload($data)
    {
        return base64_encode(json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    private function aiEnabled()
    {
        $mdl = $this->settings();
        return !empty((string)$mdl->ai->enabled) && (string)$mdl->ai->provider != 'none';
    }

    private function langChoice($value)
    {
        return in_array((string)$value, self::LANG_CHOICES, true) ? (string)$value : 'auto';
    }

    /**
     * AI state, local sources and the page language setting
     */
    public function statusAction()
    {
        $data = $this->configdJson('pa_console status', [], 30);
        $data['language'] = $this->aiLanguage();
        $data['gui_language'] = preg_match('/^[a-z]{2,3}(_[A-Z]{2})?$/', (string)$this->langcode) ?
            (string)$this->langcode : 'en_US';
        return $data;
    }

    /**
     * ready made questions in the GUI language
     */
    public function suggestAction()
    {
        return $this->configdJson('pa_console suggest', [$this->aiLanguage()], 30);
    }

    /**
     * ask the firewall: POST question, history [{q, a}] (the last turns kept by the page), language
     * (auto|pt_BR|en_US), preview=1 returns what would be sent without contacting the provider
     */
    public function askAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        $question = $this->cleanText($this->request->getPost('question'), self::MAX_QUESTION);
        if (mb_strlen($question, 'UTF-8') < 2) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Type a question.')];
        }
        $preview = !empty($this->request->getPost('preview'));
        if (!$preview && !$this->aiEnabled()) {
            return ['status' => 'disabled', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('AI assistance is disabled in the settings.')];
        }
        $history = [];
        $raw = $this->request->getPost('history');
        if (is_array($raw)) {
            foreach (array_slice($raw, -self::MAX_HISTORY) as $turn) {
                if (!is_array($turn)) {
                    continue;
                }
                $q = $this->cleanText($turn['q'] ?? '', self::MAX_HISTORY_Q);
                /* answers keep their line breaks (markdown), only NUL and other control characters go */
                $a = preg_replace('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+/u', ' ', (string)($turn['a'] ?? ''));
                $a = mb_substr(trim($a ?? ''), 0, self::MAX_HISTORY_A, 'UTF-8');
                if ($q !== '' && $a !== '') {
                    $history[] = ['q' => $q, 'a' => $a];
                }
            }
        }
        $data = ['q' => $question, 'lang' => $this->langChoice($this->request->getPost('language')),
            'history' => $history];
        /* fit the configd message: drop the oldest turns first, then shorten the remaining answers */
        while (strlen(json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) > self::MAX_PAYLOAD) {
            if (count($data['history']) > 1) {
                array_shift($data['history']);
            } elseif (count($data['history']) == 1 && mb_strlen($data['history'][0]['a'], 'UTF-8') > 200) {
                $data['history'][0]['a'] = mb_substr($data['history'][0]['a'], 0, 200, 'UTF-8');
            } elseif (count($data['history']) == 1) {
                $data['history'] = [];
            } else {
                $data['q'] = mb_substr($data['q'], 0, (int)(mb_strlen($data['q'], 'UTF-8') * 0.8), 'UTF-8');
            }
        }
        $result = $this->configdJson(
            'pa_console ask',
            [$this->payload($data), $this->aiLanguage(), $preview ? 'preview' : 'send'],
            $this->aiTimeout('console_ask') + 45
        );
        $result['history_sent'] = count($data['history']);
        return $result;
    }

    /**
     * "Explain this": POST kind (log|rule|alert), item (the fields of the row), language, preview
     */
    public function explainAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        $kind = (string)$this->request->getPost('kind');
        $item = $this->request->getPost('item');
        if (!in_array($kind, ['log', 'rule', 'alert'], true) || !is_array($item)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid item.')];
        }
        $preview = !empty($this->request->getPost('preview'));
        if (!$preview && !$this->aiEnabled()) {
            return ['status' => 'disabled', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('AI assistance is disabled in the settings.')];
        }
        $fields = [
            'log' => ['ts', 'iface', 'action', 'dir', 'proto', 'src', 'sport', 'dst', 'dport', 'rid'],
            'rule' => ['uuid', 'label'],
            'alert' => ['timestamp', 'flow_id', 'sid'],
        ][$kind];
        $data = ['lang' => $this->langChoice($this->request->getPost('language'))];
        foreach ($fields as $name) {
            if (!isset($item[$name])) {
                continue;
            }
            $value = $item[$name];
            if (in_array($name, ['flow_id', 'sid', 'ts'], true)) {
                if (!preg_match('/^[0-9]{1,20}$/', (string)$value)) {
                    return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid item.')];
                }
                /* digits as text: Suricata flow ids are 64 bit, the script converts them */
                $data[$name] = (string)$value;
            } elseif (!preg_match('/^[A-Za-z0-9.:_\/+-]{0,64}$/', (string)$value)) {
                return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid item.')];
            } else {
                $data[$name] = (string)$value;
            }
        }
        $result = $this->configdJson(
            'pa_console explain',
            [$kind, $this->payload($data), $this->aiLanguage(), $preview ? 'preview' : 'send'],
            $this->aiTimeout('console_explain_' . $kind) + 45
        );
        return $result;
    }

    /**
     * newest filter log events: ip (address or network), port, action (pass|block), iface, dir, limit
     */
    public function logAction()
    {
        $data = [];
        $ip = trim((string)$this->request->get('ip'));
        if ($ip !== '') {
            $addr = explode('/', $ip, 2);
            if (filter_var($addr[0], FILTER_VALIDATE_IP) === false ||
                (isset($addr[1]) && !preg_match('/^[0-9]{1,3}$/', $addr[1]))) {
                return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid address.')];
            }
            $data['ip'] = $ip;
        }
        $port = trim((string)$this->request->get('port'));
        if ($port !== '') {
            if (!preg_match('/^[0-9]{1,5}$/', $port) || (int)$port < 1 || (int)$port > 65535) {
                return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid port.')];
            }
            $data['port'] = (int)$port;
        }
        foreach (['action' => ['pass', 'block'], 'dir' => ['in', 'out']] as $name => $allowed) {
            if (in_array((string)$this->request->get($name), $allowed, true)) {
                $data[$name] = (string)$this->request->get($name);
            }
        }
        $iface = (string)$this->request->get('iface');
        if (preg_match('/^[A-Za-z0-9_.:-]{1,32}$/', $iface)) {
            $data['iface'] = $iface;
        }
        $limit = (int)$this->request->get('limit');
        $data['limit'] = $limit >= 10 && $limit <= 200 ? $limit : 50;
        return $this->configdJson('pa_console log', [$this->payload($data)], 30);
    }

    /**
     * rules in evaluation order with their pf counters and findings: search, iface, action, unused=1
     */
    public function rulesAction()
    {
        $data = [
            'search' => $this->cleanText($this->request->get('search'), 80),
            'unused' => !empty($this->request->get('unused')),
        ];
        $iface = (string)$this->request->get('iface');
        if (preg_match('/^[A-Za-z0-9_.:-]{1,32}$/', $iface)) {
            $data['iface'] = $iface;
        }
        if (in_array((string)$this->request->get('action'), ['pass', 'block', 'reject', 'match'], true)) {
            $data['action'] = (string)$this->request->get('action');
        }
        return $this->configdJson('pa_console rules', [$this->payload($data)], 60);
    }

    /**
     * newest Suricata alerts: severity (1..3, at most), ip, limit, days
     */
    public function alertsAction()
    {
        $data = [];
        $severity = (int)$this->request->get('severity');
        if ($severity >= 1 && $severity <= 4) {
            $data['severity'] = $severity;
        }
        $ip = trim((string)$this->request->get('ip'));
        if ($ip !== '') {
            if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
                return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid address.')];
            }
            $data['ip'] = $ip;
        }
        $limit = (int)$this->request->get('limit');
        $data['limit'] = $limit >= 10 && $limit <= 200 ? $limit : 50;
        $days = (int)$this->request->get('days');
        $data['days'] = $days >= 1 && $days <= 14 ? $days : 7;
        return $this->configdJson('pa_console alerts', [$this->payload($data)], 30);
    }
}
