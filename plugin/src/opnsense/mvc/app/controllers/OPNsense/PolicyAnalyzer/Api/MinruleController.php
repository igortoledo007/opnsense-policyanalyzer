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
 * Minimal rule from the observed traffic (read only, configd pa_minrule, see actions_pa_minrule.conf):
 *   GET  candidates                          pass rules worth narrowing (permissive / wan_exposed findings first)
 *   POST analyze uuid=<rule> days=7          observed traffic, proposal, coverage, what would be blocked
 *   POST explain uuid=<rule> days=7 [preview=1]
 * The proposal is a diff and a read-only plan: the GUI opens the rule for the administrator to edit.
 */
class MinruleController extends ApiControllerBase
{
    use ApiHelperTrait;

    private const RULE_ID = '/^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|legacy-[0-9]{1,5})$/';

    private function params()
    {
        $uuid = (string)$this->request->get('uuid');
        $days = (string)$this->request->get('days');
        if (!preg_match('/^[0-9]{1,2}$/', $days) || (int)$days < 1 || (int)$days > 30) {
            $days = '7';
        }
        return [preg_match(self::RULE_ID, $uuid) ? $uuid : null, $days];
    }

    public function candidatesAction()
    {
        return $this->configdJson('pa_minrule candidates', [], 60);
    }

    public function analyzeAction()
    {
        list($uuid, $days) = $this->params();
        if ($uuid === null) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid rule id.')];
        }
        /* NetFlow fallback reads up to 20 s of flows, the filter log scan is fast */
        return $this->configdJson('pa_minrule analyze', [$uuid, $days], 120);
    }

    public function explainAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        list($uuid, $days) = $this->params();
        if ($uuid === null) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid rule id.')];
        }
        $preview = !empty($this->request->getPost('preview'));
        $mdl = $this->settings();
        if (!$preview && (empty((string)$mdl->ai->enabled) || (string)$mdl->ai->provider == 'none')) {
            return ['status' => 'disabled', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('AI assistance is disabled in the settings.')];
        }
        return $this->configdJson(
            'pa_minrule explain',
            [$uuid, $days, $this->aiLanguage(), $preview ? 'preview' : 'send'],
            $this->aiTimeout('minrule_explain') + 90
        );
    }
}
