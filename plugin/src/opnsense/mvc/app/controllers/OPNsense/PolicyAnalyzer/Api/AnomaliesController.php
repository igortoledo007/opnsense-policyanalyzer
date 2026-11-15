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
 * Anomalies of the LAN (lightweight NDR), scripts/policyanalyzer/anomalies (configd: actions_pa_anomalies.conf).
 *
 * Read (view privilege):
 *   GET  summary                 light counters + the 10 latest open findings (Max Cyber widget)
 *   GET  status                  installation, cron, sources, last runs and their cost, parameters, network
 *   GET|POST search              current, rowCount, sort[field]=asc|desc, searchPhrase + status, severity, type,
 *                                host, days
 *   GET  finding  id=<16 hex>    one finding: factors, evidence, occurrences, sparkline series, suggested actions
 *   GET  host     ip=<address>   host profile: what is normal for it vs. now
 * AI (admin privilege, text only, never applied):
 *   POST explain  kind=finding|host, id=<finding id|address>, preview=1 (what would be sent)
 * Change (admin privilege; simulated first, journaled, revertible):
 *   POST plan|apply  action=<install_anomalies|remove_anomalies|anomaly_expect|anomaly_exception_del|
 *                    anomaly_resolve|anomaly_settings|revert>, args[]
 *   POST run         one detection run now (the same as the cron job)
 */
class AnomaliesController extends ApiControllerBase
{
    use ApiHelperTrait;

    private const ACTIONS = ['install_anomalies', 'remove_anomalies', 'anomaly_expect', 'anomaly_exception_del',
                             'anomaly_resolve', 'anomaly_settings', 'revert'];
    private const FILTERS = [
        'status' => '/^(open|expected|resolved)$/',
        'severity' => '/^(high|medium|low|info)$/',
        'type' => '/^[a-z_]{2,24}$/',
        'host' => '/^[0-9A-Fa-f:.]{2,45}$/',
        'days' => '/^[0-9]{1,4}$/',
    ];
    private const SORTABLE = ['severity', 'score', 'last_seen', 'first_seen', 'host', 'type', 'occurrences', 'status'];
    private const ANOMALY_ID = '/^[0-9a-f]{16}$/';

    public function summaryAction()
    {
        return $this->configdJson('pa_anomalies summary', [], 30);
    }

    public function statusAction()
    {
        return $this->configdJson('pa_anomalies status', [], 30);
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
        $rows = (int)$this->request->get('rowCount', 'int', 25);
        $rows = $rows === -1 ? -1 : max(1, min($rows, 500));
        $data = $this->configdJson('pa_anomalies list', [
            empty($filters) ? '-' : implode('+', $filters), $sort, $current . ':' . $rows], 60);
        if (($data['status'] ?? '') !== 'ok') {
            return ['rows' => [], 'rowCount' => 0, 'total' => 0, 'current' => $current,
                    'message' => $data['message'] ?? ''];
        }
        return $data;
    }

    public function findingAction()
    {
        $id = (string)$this->request->get('id');
        if (!preg_match(self::ANOMALY_ID, $id)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid finding id.')];
        }
        return $this->configdJson('pa_anomalies finding', [$id], 30);
    }

    public function hostAction()
    {
        $ip = trim((string)$this->request->get('ip'));
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid address.')];
        }
        return $this->configdJson('pa_anomalies host', [$ip], 30);
    }

    public function explainAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        $kind = (string)$this->request->getPost('kind');
        $id = trim((string)$this->request->getPost('id'));
        if ($kind === 'finding') {
            if (!preg_match(self::ANOMALY_ID, $id)) {
                return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid finding id.')];
            }
        } elseif ($kind === 'host') {
            if (filter_var($id, FILTER_VALIDATE_IP) === false) {
                return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid address.')];
            }
        } else {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid request.')];
        }
        $preview = !empty($this->request->getPost('preview'));
        $mdl = $this->settings();
        if (!$preview && (empty((string)$mdl->ai->enabled) || (string)$mdl->ai->provider == 'none')) {
            return ['status' => 'disabled', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('AI assistance is disabled in the settings.')];
        }
        return $this->configdJson(
            'pa_anomalies explain',
            [$kind, $id, $this->aiLanguage(), $preview ? 'preview' : 'send'],
            $this->aiTimeout($kind === 'host' ? 'anomaly_host' : 'anomaly_explain') + 30
        );
    }

    public function planAction()
    {
        return $this->change('plan');
    }

    public function applyAction()
    {
        return $this->change('apply');
    }

    public function runAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        return $this->configdJson('pa_anomalies run', [], 300);
    }

    private function change($mode)
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
        if ($action == 'revert' && !preg_match(self::JOURNAL_ID, $args[0] ?? '')) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid journal id.')];
        }
        return $this->configdJson('pa_anomalies ' . $mode, array_merge([$action], $args), $mode == 'apply' ? 300 : 60);
    }
}
