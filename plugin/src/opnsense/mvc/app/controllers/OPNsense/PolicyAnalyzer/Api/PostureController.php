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
 * Posture health check (read only, configd pa_posture, see actions_pa_posture.conf):
 *   GET  report             last stored report (runs the checks once when none exists)
 *   POST run               run the checks now, store the report and one history row
 *   GET  summary            light document for widgets (score, grade, counts, top failures, trend)
 *   GET  history?days=90    score history
 *   GET  checks             catalogue of the checks
 *   POST explain id=<PA-XXX-NN>|summary [preview=1]
 *                           AI explanation of one check, or the executive summary (text only)
 */
class PostureController extends ApiControllerBase
{
    use ApiHelperTrait;

    /** check ids: PA-ACC-01 (see scripts/policyanalyzer/posture/checks.py) */
    private const CHECK_ID = '/^[A-Z]{2,4}-[A-Z]{2,4}-[0-9]{2}$/';

    public function reportAction()
    {
        return $this->configdJson('pa_posture last', [], 60);
    }

    public function runAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        return $this->configdJson('pa_posture run', [], 60);
    }

    public function summaryAction()
    {
        return $this->configdJson('pa_posture summary', [], 30);
    }

    public function historyAction()
    {
        $days = (string)$this->request->get('days');
        if (!preg_match('/^[0-9]{1,3}$/', $days) || (int)$days < 1 || (int)$days > 400) {
            $days = '90';
        }
        return $this->configdJson('pa_posture history', [$days], 30);
    }

    public function checksAction()
    {
        return $this->configdJson('pa_posture checks', [], 30);
    }

    public function explainAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        $id = (string)$this->request->getPost('id');
        if ($id !== 'summary' && !preg_match(self::CHECK_ID, $id)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid check id.')];
        }
        $preview = !empty($this->request->getPost('preview'));
        $mdl = $this->settings();
        if (!$preview && (empty((string)$mdl->ai->enabled) || (string)$mdl->ai->provider == 'none')) {
            return ['status' => 'disabled', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('AI assistance is disabled in the settings.')];
        }
        return $this->configdJson(
            'pa_posture explain',
            [$id, $this->aiLanguage(), $preview ? 'preview' : 'send'],
            $this->aiTimeout($id === 'summary' ? 'posture_summary' : 'posture_check') + 30
        );
    }
}
