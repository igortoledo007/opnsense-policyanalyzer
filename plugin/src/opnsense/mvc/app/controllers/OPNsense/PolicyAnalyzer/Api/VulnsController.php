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
 * Vulnerability prioritisation (/api/policyanalyzer/vulns/*), backend scripts/policyanalyzer/vulns/.
 * Read only on the firewall; the network is used only by the change action vulns_intel_update.
 *
 *   GET  summary                 light counts (Max Cyber, reports)
 *   GET  list?priority=P1+P2     prioritised CVEs with factors, review queue, KEV/EPSS cache state
 *   GET  cve?id=CVE-...          one item
 *   GET  intel                   KEV / EPSS cache dates and coverage
 *   GET  explain?cve=            stored AI explanation;  POST explain {cve, mode: refresh|preview}
 *   POST suggest {id, mode: refresh|preview}   AI mapping suggestion of a review item
 *   POST plan|apply {action, args[]}  vulns_intel_update, vulns_review_decide, revert
 */
class VulnsController extends ApiControllerBase
{
    use ApiHelperTrait;
    use ModuleHelperTrait;

    private const ACTIONS = ['vulns_intel_update' => 1, 'vulns_review_decide' => 3, 'revert' => 2];
    private const CVE = '/^CVE-[0-9]{4}-[0-9]{4,7}$/';

    public function summaryAction()
    {
        return $this->configdJson('pa_vulns summary', [], 60);
    }

    public function listAction()
    {
        $prio = (string)$this->request->get('priority', null, 'all');
        if (!preg_match('/^(all|P[1-4](\+P[1-4]){0,3})$/', $prio)) {
            $prio = 'all';
        }
        return $this->configdJson('pa_vulns list', [$prio], 60);
    }

    public function cveAction()
    {
        $cve = strtoupper((string)$this->request->get('id', null, ''));
        if (!preg_match(self::CVE, $cve)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid CVE id.')];
        }
        return $this->configdJson('pa_vulns cve', [$cve], 60);
    }

    public function intelAction()
    {
        return $this->configdJson('pa_vulns intel', [], 30);
    }

    public function explainAction()
    {
        $post = $this->request->isPost();
        $cve = strtoupper((string)($post ? $this->request->getPost('cve') : $this->request->get('cve', null, '')));
        if (!preg_match(self::CVE, $cve)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid CVE id.')];
        }
        $mode = $post ? (string)$this->request->getPost('mode') : 'cached';
        if (!in_array($mode, ['cached', 'refresh', 'preview'], true)) {
            $mode = 'cached';
        }
        return $this->configdJson('pa_vulns explain', [$cve, $this->aiLanguage(), $mode],
            $mode === 'refresh' ? $this->aiTimeout('explain_cve') + 30 : 60);
    }

    public function suggestAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        $id = (string)$this->request->getPost('id');
        if (!preg_match('/^[0-9a-f]{12}$/', $id)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid id.')];
        }
        $mode = $this->request->getPost('mode') === 'preview' ? 'preview' : 'refresh';
        return $this->configdJson('pa_vulns suggest', [$id, $this->aiLanguage(), $mode],
            $mode === 'refresh' ? $this->aiTimeout('vuln_review_suggest') + 30 : 60);
    }

    public function planAction()
    {
        return $this->moduleChange('pa_vulns', self::ACTIONS, 'plan');
    }

    public function applyAction()
    {
        return $this->moduleChange('pa_vulns', self::ACTIONS, 'apply');
    }
}
