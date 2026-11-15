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

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Base\FieldTypes\UpdateOnlyTextField;
use OPNsense\Core\Config;

/**
 * Settings of the Policy Analyzer and its AI layer.
 *
 * Every save is journaled (snapshot before, record after) so it can be reverted from the action history.
 * Secrets (UpdateOnlyTextField) are never returned, only a "****1234" hint.
 */
class SettingsController extends ApiMutableModelControllerBase
{
    use ApiHelperTrait;

    protected static $internalModelClass = '\OPNsense\PolicyAnalyzer\PolicyAnalyzer';
    protected static $internalModelName = 'policyanalyzer';

    /**
     * {@inheritdoc}, plus "secret_hints" for write-only fields
     */
    public function getAction()
    {
        $result = parent::getAction();
        if (!empty($result)) {
            $result['secret_hints'] = $this->secretHints();
        }
        return $result;
    }

    /**
     * {@inheritdoc}, journaled
     */
    public function setAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $this->settingsJournal('snapshot');
        $result = parent::setAction();
        if (($result['result'] ?? '') == 'saved') {
            $result['journal_id'] = $this->settingsJournal('record');
        }
        return $result;
    }

    /**
     * clear a write-only field (e.g. claude.apikey), journaled so it can be restored
     */
    public function clearSecretAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $field = (string)$this->request->getPost('field');
        $node = $this->secretNode($field);
        if ($node === null) {
            return ['result' => 'failed', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Unknown field.')];
        }
        Config::getInstance()->lock();
        $this->settingsJournal('snapshot');
        $node->applyDefault();
        $this->save(false, true);
        return ['result' => 'saved', 'journal_id' => $this->settingsJournal('record')];
    }

    private function secretNode($path)
    {
        if (!preg_match('/^[a-z0-9_]+\.[a-z0-9_]+$/', $path)) {
            return null;
        }
        $node = $this->getModel()->getNodeByReference($path);
        return $node instanceof UpdateOnlyTextField ? $node : null;
    }

    private function secretHints()
    {
        $hints = [];
        foreach ($this->getModel()->getFlatNodes() as $key => $node) {
            if ($node instanceof UpdateOnlyTextField) {
                $value = $node->getValue();
                $hints[$key] = $value === '' ? '' : '****' . substr($value, -4);
            }
        }
        return $hints;
    }
}
