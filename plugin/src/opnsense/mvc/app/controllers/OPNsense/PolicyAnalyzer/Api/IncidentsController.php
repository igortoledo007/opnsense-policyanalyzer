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
 * Incidents: correlated triage of the Suricata alerts, the filter log, the quarantine and the blocked DNS
 * queries into cases (scripts/policyanalyzer/incidents, configd service "pa_incidents").
 *
 * Read (view privilege):
 *   GET  status                     installed, cron job, sources, counters, last run
 *   GET  summary                    light: open cases by severity, new in 24 h, the latest 10 (Max Cyber widget)
 *   GET  search                     state (open|new|investigating|resolved|false_positive), severity, rule, days,
 *                                   search, sort (last_activity|score|created|id), dir, page, rows
 *   GET  case                       id=<n>: entities, rules, evidence timeline, notes, history, last AI summary
 *   GET  digest                     day=YYYY-MM-DD|today: the stored daily digest and the totals of the day
 * AI (admin privilege, POST; text only, nothing is applied):
 *   POST summarize {id, preview}    summary, hypothesis, impact, next steps, suggested actions (closed list)
 *   POST digest {day, mode=generate}
 * Change (admin privilege, POST, journaled in the action history, revertible):
 *   POST state {id, state, note}, note {id, note}, run (correlation now)
 *   POST plan|apply {action, args[]}  install_incidents, remove_incidents, incident_state, incident_note
 *                                   (the simulation dialog uses this endpoint for the incidents actions)
 */
class IncidentsController extends ApiControllerBase
{
    use ApiHelperTrait;

    private const ACTIONS = ['install_incidents', 'remove_incidents', 'incident_state', 'incident_note', 'incidents_tidy'];
    private const STATES = ['new', 'investigating', 'resolved', 'false_positive'];
    private const FILTERS = [
        'state' => '/^(open|new|investigating|resolved|false_positive)$/',
        'severity' => '/^(critical|high|medium|low)$/',
        'rule' => '/^(scan_then_allowed|ids_and_allowed|internal_to_bad|campaign|repeat_offender|port_spike)$/',
        'days' => '/^[0-9]{1,4}$/',
    ];
    private const SORTABLE = ['last_activity', 'score', 'created', 'id', 'state', 'first_seen'];

    public function statusAction()
    {
        $data = $this->configdJson('pa_incidents status', [], 30);
        $mdl = $this->settings();
        $data['ai_enabled'] = !empty((string)$mdl->ai->enabled) && (string)$mdl->ai->provider != 'none';
        return $data;
    }

    public function summaryAction()
    {
        return $this->configdJson('pa_incidents summary', [], 30);
    }

    public function searchAction()
    {
        $filters = [];
        foreach (self::FILTERS as $key => $regex) {
            $value = (string)$this->request->get($key, null, '');
            if ($value !== '' && preg_match($regex, $value)) {
                $filters[] = $key . '=' . $value;
            }
        }
        $phrase = trim((string)$this->request->get('search', null, ''));
        if ($phrase === '') {
            $phrase = trim((string)$this->request->get('searchPhrase', null, ''));
        }
        if ($phrase !== '' && preg_match('/^[0-9A-Za-z:.\/_-]{1,64}$/', $phrase)) {
            $filters[] = 'search=' . $phrase;
        }
        $sort = (string)$this->request->get('sort', null, 'last_activity');
        $sort = in_array($sort, self::SORTABLE, true) ? $sort : 'last_activity';
        $dir = (string)$this->request->get('dir', null, 'desc') === 'asc' ? 'asc' : 'desc';
        $page = max(1, (int)$this->request->get('page', 'int', 1));
        $rows = max(1, min((int)$this->request->get('rows', 'int', 25), 200));
        $data = $this->configdJson('pa_incidents list', [
            empty($filters) ? '-' : implode('+', $filters), $sort . ':' . $dir, $page . ':' . $rows], 60);
        if (($data['status'] ?? '') !== 'ok') {
            return array_merge(['rows' => [], 'total' => 0, 'current' => $page], $data);
        }
        return $data;
    }

    private function caseId($post = false)
    {
        $id = (string)($post ? $this->request->getPost('id', null, '') : $this->request->get('id', null, ''));
        return preg_match('/^[0-9]{1,9}$/', $id) ? $id : null;
    }

    public function caseAction()
    {
        $id = $this->caseId();
        if ($id === null) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid case.')];
        }
        return $this->configdJson('pa_incidents case', [$id], 60);
    }

    private function aiEnabled()
    {
        $mdl = $this->settings();
        return !empty((string)$mdl->ai->enabled) && (string)$mdl->ai->provider != 'none';
    }

    public function summarizeAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        $id = $this->caseId(true);
        if ($id === null) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid case.')];
        }
        $preview = !empty($this->request->getPost('preview'));
        if (!$preview && !$this->aiEnabled()) {
            return ['status' => 'disabled', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('AI assistance is disabled in the settings.')];
        }
        return $this->configdJson('pa_incidents summarize', [$id, $this->aiLanguage(), $preview ? 'preview' : 'send'],
            $this->aiTimeout('incident_summary') + 30);
    }

    public function digestAction()
    {
        $day = (string)$this->request->get('day', null, 'today');
        if ($day !== 'today' && !preg_match('/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/', $day)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid day.')];
        }
        $mode = 'cached';
        if ($this->request->isPost() && (string)$this->request->getPost('mode') === 'generate') {
            if (!$this->aiEnabled()) {
                return ['status' => 'disabled', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('AI assistance is disabled in the settings.')];
            }
            $mode = 'generate';
        }
        return $this->configdJson('pa_incidents digest', [$day, $this->aiLanguage(), $mode],
            $mode === 'generate' ? $this->aiTimeout('incident_digest') + 30 : 60);
    }

    /**
     * note text (UTF-8, cut at 180 bytes) as base64: fits the 255 characters of a configd argument
     * @return string|null "-" when empty, null when too long
     */
    private function noteToken($text)
    {
        $text = trim(preg_replace('/[\x00-\x09\x0b-\x1f\x7f]/u', '', (string)$text));
        if ($text === '') {
            return '-';
        }
        $text = mb_strcut($text, 0, 180, 'UTF-8');
        return base64_encode($text);
    }

    public function stateAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        $id = $this->caseId(true);
        $state = (string)$this->request->getPost('state', null, '');
        if ($id === null || !in_array($state, self::STATES, true)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid case or state.')];
        }
        return $this->configdJson('pa_incidents apply',
            ['incident_state', $id, $state, $this->noteToken($this->request->getPost('note', null, ''))], 60);
    }

    public function noteAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        $id = $this->caseId(true);
        $note = $this->noteToken($this->request->getPost('note', null, ''));
        if ($id === null || $note === '-') {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Enter a note.')];
        }
        return $this->configdJson('pa_incidents apply', ['incident_note', $id, $note], 60);
    }

    public function runAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        return $this->configdJson('pa_incidents run', [], 120);
    }

    /**
     * @return array configd parameters [action, arg...] or an error structure
     */
    private function changeParams()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        $action = (string)$this->request->getPost('action');
        if (!in_array($action, self::ACTIONS, true)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid action.')];
        }
        $args = array_values((array)$this->request->getPost('args', null, []));
        if (count($args) > 3) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Too many arguments.')];
        }
        foreach ($args as $arg) {
            if (!is_string($arg) || !preg_match(self::ARG_TOKEN, $arg)) {
                return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid argument.')];
            }
        }
        return array_merge([$action], $args);
    }

    public function planAction()
    {
        $params = $this->changeParams();
        return isset($params['status']) ? $params : $this->configdJson('pa_incidents plan', $params, 60);
    }

    public function applyAction()
    {
        $params = $this->changeParams();
        return isset($params['status']) ? $params : $this->configdJson('pa_incidents apply', $params, 300);
    }
}
