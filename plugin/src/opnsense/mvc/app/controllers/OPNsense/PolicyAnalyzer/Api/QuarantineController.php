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
use OPNsense\Core\Backend;

/**
 * Automatic quarantine (Max Cyber IA), see CONTRACT.md ("Automatic quarantine").
 *
 * Read (view privilege):
 *   GET  status                         state, counts per level, last run, warnings with their actions
 *   GET  summary                        light: counts + the latest 20 entries (Max Cyber widget)
 *   GET|POST search                     bootgrid: current, rowCount, sort, searchPhrase + state, reason, origin,
 *                                       country, asn, year, level
 *   GET  history                        kind=offenses|events|yearly, ip, year | from+to (YYYY-MM-DD), page, rows
 *   GET  export                         CSV of the offenses of a year (or from/to), optional ip
 *   GET  entry                          id=<n> | ip=<address>: one entry with its whole history
 *   GET  guards                         addresses that are never quarantined
 *   GET  wizard                         state of every step of the quarantine assistant (detected now)
 *   GET  preview                        settings=<key=value:...|-|defaults>: what the scenarios would decide with
 *                                       the logs of the last 5 minutes (nothing is written)
 * Change (admin privilege; journaled, revertible from the action history):
 *   POST release {ids | ip}, add {target, duration, comment}, pause, resume
 *   everything else (extend, permanent, never block, settings, install, remove and the steps of the assistant,
 *   qsetup_*) uses /api/policyanalyzer/change
 */
class QuarantineController extends ApiControllerBase
{
    use ApiHelperTrait;

    private const FILTERS = [
        'state' => '/^(active|expired|released|permanent|blocked)$/',
        'reason' => '/^(base|scan|bait|suricata|manual)$/',
        'origin' => '/^(auto|manual)$/',
        'country' => '/^[A-Z]{2}$/',
        'asn' => '/^[0-9]{1,10}$/',
        'year' => '/^[0-9]{4}$/',
        'level' => '/^[1-6]$/',
    ];
    private const SORTABLE = ['addr', 'first_seen', 'last_offense', 'level', 'until', 'offenses', 'country', 'asn',
                              'state', 'reason', 'origin', 'hits'];
    private const DURATIONS = ['auto', 'l1', 'l2', 'l3', 'l4', 'l5', 'permanent'];

    public function statusAction()
    {
        return $this->configdJson('policyanalyzer quarantine_status', [], 60);
    }

    public function summaryAction()
    {
        return $this->configdJson('policyanalyzer quarantine_summary', [], 30);
    }

    public function guardsAction()
    {
        return $this->configdJson('policyanalyzer quarantine_guards', [], 60);
    }

    public function wizardAction()
    {
        return $this->configdJson('policyanalyzer quarantine_wizard', [], 90);
    }

    public function previewAction()
    {
        $token = (string)$this->request->get('settings', null, '-');
        if (!preg_match('/^(-|defaults|[a-z_]{1,24}=[0-9+]{1,200}(:[a-z_]{1,24}=[0-9+]{1,200}){0,8})$/', $token) ||
            strlen($token) > 255) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid settings.')];
        }
        return $this->configdJson('policyanalyzer quarantine_preview', [$token], 60);
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
        $phrase = trim((string)$this->request->get('searchPhrase', null, ''));
        if ($phrase !== '' && preg_match('/^[0-9A-Za-z:.\/_-]{1,64}$/', $phrase)) {
            $filters[] = 'search=' . $phrase;
        }
        $sort = '-';
        $sortReq = $this->request->get('sort');
        if (is_array($sortReq)) {
            foreach ($sortReq as $field => $dir) {
                if (in_array($field, self::SORTABLE, true)) {
                    $sort = $field . ':' . ($dir === 'asc' ? 'asc' : 'desc');
                }
                break;
            }
        }
        $current = max(1, (int)$this->request->get('current', 'int', 1));
        $rows = (int)$this->request->get('rowCount', 'int', 20);
        $rows = $rows === -1 ? -1 : max(1, min($rows, 500));
        $data = $this->configdJson('policyanalyzer quarantine_list', [
            empty($filters) ? '-' : implode('+', $filters), $sort, $current . ':' . $rows], 60);
        if (($data['status'] ?? '') !== 'ok') {
            return ['rows' => [], 'rowCount' => 0, 'total' => 0, 'current' => $current,
                    'message' => $data['message'] ?? ''];
        }
        return $data;
    }

    /**
     * @return string "-", "YYYY" or "YYYYMMDD-YYYYMMDD", or null when invalid
     */
    private function period()
    {
        $year = (string)$this->request->get('year', null, '');
        $from = (string)$this->request->get('from', null, '');
        $to = (string)$this->request->get('to', null, '');
        if ($year !== '') {
            return preg_match('/^[0-9]{4}$/', $year) ? $year : null;
        }
        if ($from !== '' || $to !== '') {
            if (!preg_match('/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/', $from) || !preg_match('/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/', $to)) {
                return null;
            }
            return str_replace('-', '', $from) . '-' . str_replace('-', '', $to);
        }
        return '-';
    }

    /**
     * address filter of the history: an address, a network prefix or "AS<n>"; "-" when empty
     */
    private function addressFilter()
    {
        $ip = trim((string)$this->request->get('ip', null, ''));
        if ($ip === '') {
            return '-';
        }
        return preg_match('/^[0-9A-Fa-f:.\/]{1,64}$|^AS[0-9]{1,10}$/', $ip) ? $ip : null;
    }

    public function historyAction()
    {
        $kind = (string)$this->request->get('kind', null, 'offenses');
        if (!in_array($kind, ['offenses', 'events', 'yearly'], true)) {
            $kind = 'offenses';
        }
        $period = $this->period();
        $ip = $this->addressFilter();
        if ($period === null || $ip === null) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid filter.')];
        }
        $page = max(1, (int)$this->request->get('page', 'int', 1));
        $rows = max(1, min((int)$this->request->get('rows', 'int', 50), 500));
        return $this->configdJson('policyanalyzer quarantine_history', [$kind, $ip, $period, $page . ':' . $rows], 60);
    }

    public function exportAction()
    {
        $period = $this->period();
        $ip = $this->addressFilter();
        if ($period === null || $ip === null) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid filter.')];
        }
        $name = 'quarantine-' . ($period === '-' ? 'all' : $period) . ($ip !== '-' ? '-' . preg_replace('/[^0-9A-Za-z.]/', '_', $ip) : '')
            . '.csv';
        $headers = ['Content-Type: text/csv; charset=utf-8', 'Content-Disposition: attachment; filename=' . $name,
                    'Content-Transfer-Encoding: binary', 'Pragma: no-cache', 'Expires: 0'];
        if (method_exists($this, 'configdStream')) {
            return $this->configdStream('policyanalyzer quarantine_export', [$period, $ip], $headers, 120, true);
        }
        $csv = (new Backend())->configdpRun('policyanalyzer quarantine_export', [$period, $ip], false, 120);
        foreach ($headers as $header) {
            $parts = explode(':', $header, 2);
            $this->response->setHeader($parts[0], ltrim($parts[1]));
        }
        $this->response->setContent((string)$csv);
    }

    public function entryAction()
    {
        $id = (string)$this->request->get('id', null, '');
        $ip = (string)$this->request->get('ip', null, '');
        if (preg_match('/^[0-9]{1,9}$/', $id)) {
            return $this->configdJson('policyanalyzer quarantine_entry', [$id], 60);
        }
        if (preg_match('/^[0-9A-Fa-f:.\/]{1,64}$|^AS[0-9]{1,10}$/', $ip)) {
            return $this->configdJson('policyanalyzer quarantine_entry', [$ip], 60);
        }
        return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid entry.')];
    }

    /**
     * a manual target: address, CIDR, range "first-last" or "AS<number>" (the backend checks the guards)
     */
    public static function validTarget($target)
    {
        if (preg_match('/^AS[0-9]{1,10}$/', $target)) {
            return true;
        }
        if (strpos($target, '-') !== false) {
            $parts = explode('-', $target);
            return count($parts) === 2 && filter_var($parts[0], FILTER_VALIDATE_IP) !== false &&
                filter_var($parts[1], FILTER_VALIDATE_IP) !== false;
        }
        $parts = explode('/', $target);
        if (count($parts) > 2 || filter_var($parts[0], FILTER_VALIDATE_IP) === false) {
            return false;
        }
        if (count($parts) === 2) {
            $max = strpos($parts[0], ':') !== false ? 128 : 32;
            return preg_match('/^[0-9]{1,3}$/', $parts[1]) && (int)$parts[1] <= $max;
        }
        return true;
    }

    private function change($action, $args)
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        foreach ($args as $arg) {
            if (!is_string($arg) || !preg_match(self::ARG_TOKEN, $arg)) {
                return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid argument.')];
            }
        }
        return $this->configdJson('policyanalyzer change_apply', array_merge([$action], $args), 300);
    }

    public function releaseAction()
    {
        $ids = (string)$this->request->getPost('ids', null, '');
        $ip = trim((string)$this->request->getPost('ip', null, ''));
        if ($ids === '' && $ip !== '') {
            if (!self::validTarget($ip)) {
                return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid address.')];
            }
            $entry = $this->configdJson('policyanalyzer quarantine_entry', [$ip], 60);
            if (!isset($entry['entry']['id'])) {
                return ['status' => 'error', 'message' => $entry['message'] ?? \OPNsense\PolicyAnalyzer\L10n::t('Entry not found.')];
            }
            $ids = (string)$entry['entry']['id'];
        }
        if (!preg_match('/^[0-9]{1,9}(\+[0-9]{1,9}){0,29}$/', $ids)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid selection.')];
        }
        return $this->change('quarantine_release', [$ids]);
    }

    public function addAction()
    {
        $target = trim((string)$this->request->getPost('target', null, ''));
        $duration = (string)$this->request->getPost('duration', null, 'auto');
        $comment = (string)$this->request->getPost('comment', null, '');
        if (!self::validTarget($target)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Enter an address, a network (CIDR), a range (first-last) or an ASN (AS64500).')];
        }
        if (!in_array($duration, self::DURATIONS, true)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid duration.')];
        }
        /* never lock out the session that asks */
        $remote = $this->request->getClientAddress();
        if ($remote !== null && $remote === $target) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('This is the address of your own session.')];
        }
        /* base64 of at most 180 bytes fits the 255 characters of a configd argument */
        $comment = mb_strcut(trim(preg_replace('/[\x00-\x1f\x7f]/u', '', $comment)), 0, 180, 'UTF-8');
        return $this->change('quarantine_add', [$target, $duration, $comment === '' ? '-' : base64_encode($comment)]);
    }

    public function pauseAction()
    {
        return $this->change('quarantine_pause', []);
    }

    public function resumeAction()
    {
        return $this->change('quarantine_resume', []);
    }
}
