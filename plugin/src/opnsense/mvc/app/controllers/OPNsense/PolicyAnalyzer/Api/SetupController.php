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
 * Read-only probes used by the AI setup assistant (/ui/policyanalyzer/setup).
 * Nothing here changes anything: the assistant applies its steps through ChangeController (plan/apply/revert)
 * and SettingsController (journaled set).
 */
class SetupController extends ApiControllerBase
{
    use ApiHelperTrait;

    /** product description written by the firmware (never user supplied) */
    private const VERSION_FILE = '/usr/local/opnsense/version/core';

    /**
     * hardware profile for the "Check" step: CPU model/threads/flags, RAM, GPUs, load, heavy services,
     * free space of the models directory, current limits (manage.py status hw_profile), plus the product version
     */
    public function hwprofileAction()
    {
        $data = $this->configdJson('policyanalyzer ai_hw_profile', [], 60);
        $data['product'] = $this->productInfo();
        return $data;
    }

    /**
     * quick test of the local AI (step 7): one real, short question with today's date and a random topic, sent to
     * the Ollama of the jail. Read only. POST model=name:tag
     */
    public function quicktestAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Use POST.')];
        }
        $model = (string)$this->request->getPost('model');
        if (!preg_match('/^[a-z0-9][a-z0-9._\/-]{0,99}(:[a-z0-9][a-z0-9._-]{0,63})?$/', $model)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid model name.')];
        }
        return $this->configdJson('policyanalyzer ai_quick_test', [$model], 320);
    }

    /**
     * @return array product name, version, ABI and architecture of this firewall
     */
    private function productInfo()
    {
        $info = ['name' => null, 'version' => null, 'abi' => null, 'arch' => null];
        $raw = @file_get_contents(self::VERSION_FILE);
        $core = json_decode((string)$raw, true);
        if (is_array($core)) {
            $info['name'] = isset($core['product_name']) ? (string)$core['product_name'] : null;
            $info['version'] = isset($core['product_version']) ? (string)$core['product_version'] : null;
            $info['abi'] = isset($core['product_abi']) ? (string)$core['product_abi'] : null;
            $info['arch'] = isset($core['product_arch']) ? (string)$core['product_arch'] : null;
        }
        return $info;
    }
}
