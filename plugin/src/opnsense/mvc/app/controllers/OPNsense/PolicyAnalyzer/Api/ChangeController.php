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
 * Generic "simulate, then apply" endpoints for every action that changes the system, plus revert and history.
 *
 *   POST plan   {action, args[]}  -> plan (steps, warnings, irreversible, risk), nothing changes
 *   POST apply  {action, args[]}  -> runs the plan recomputed by the backend, writes an undo journal entry
 *   POST plan   {action: "revert", args: [<journal id>]}
 *   POST apply  {action: "revert", args: [<journal id>]}
 *   GET  history                  -> journal entries, newest first
 *   GET  actions                  -> registered actions
 *
 * Arguments are simple tokens; actions whose argument comes from the saved settings resolve it here
 * (see $modelArgs), so the browser can not point them elsewhere.
 */
class ChangeController extends ApiMutableModelControllerBase
{
    use ApiHelperTrait;

    protected static $internalModelClass = '\OPNsense\PolicyAnalyzer\PolicyAnalyzer';
    protected static $internalModelName = 'policyanalyzer';

    /**
     * action => list of model references used as its arguments (instead of client supplied ones).
     * New actions (install_runtime, pull_model, set_limits, ...) add their entry here when needed.
     */
    protected static $modelArgs = [
        'prepare_storage' => ['ollama.models_dir'],
    ];

    /** maximum number of arguments forwarded to configd (see actions_policyanalyzer.conf) */
    private const MAX_ARGS = 5;

    public function actionsAction()
    {
        return $this->configdJson('policyanalyzer change_list');
    }

    public function historyAction()
    {
        return $this->configdJson('policyanalyzer change_history');
    }

    public function planAction()
    {
        $params = $this->params();
        if (isset($params['status'])) {
            return $params;
        }
        return $this->hideValues($this->configdJson('policyanalyzer change_plan', $params, 120));
    }

    public function applyAction()
    {
        $params = $this->params();
        if (isset($params['status'])) {
            return $params;
        }
        $this->throwReadOnly();
        $result = $this->configdJson('policyanalyzer change_apply', $params, 3600);
        if (($result['apply_via'] ?? '') == 'gui' && ($result['reverts'] ?? '') == 'settings') {
            /* settings are restored through the model, using the values the backend computed */
            $saved = $this->restoreValues(is_array($result['values'] ?? null) ? $result['values'] : []);
            if (($saved['result'] ?? '') != 'saved') {
                return ['status' => 'error', 'done' => false, 'validations' => $saved['validations'] ?? [],
                        'message' => \OPNsense\PolicyAnalyzer\L10n::t('The previous values do not validate anymore.')];
            }
            $this->settingsJournal('reverted', [$params[1]]);
            $result['done'] = true;
            $result['completed'] = array_column($result['steps'] ?? [], 'description');
            $result['journal_id'] = $saved['journal_id'] ?? null;
        }
        return $this->hideValues($result);
    }

    /**
     * restore values of a settings journal entry through the model (validation and config handling as usual)
     * @param array $values flattened field => value map computed by the backend, never by the browser
     * @return array status or validation errors
     */
    private function restoreValues(array $values)
    {
        Config::getInstance()->lock();
        $this->settingsJournal('snapshot');
        $mdl = $this->getModel();
        foreach ($values as $path => $value) {
            $node = $mdl->getNodeByReference($path);
            if ($node === null || $node->isContainer()) {
                continue;
            }
            if ($node instanceof UpdateOnlyTextField && $value === '') {
                $node->applyDefault();
            } else {
                $node->setValue($value);
            }
        }
        $result = $this->validate();
        if (!empty($result['result'])) {
            return $result;
        }
        $this->save(false, true);
        return ['result' => 'saved', 'journal_id' => $this->settingsJournal('record')];
    }

    /**
     * @return array configd parameters [action, arg...] or an error structure
     */
    private function params()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        $action = (string)$this->request->getPost('action');
        if (!preg_match(self::ACTION_NAME, $action)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid action.')];
        }
        if (isset(static::$modelArgs[$action])) {
            $mdl = $this->getModel();
            $args = [];
            foreach (static::$modelArgs[$action] as $ref) {
                $node = $mdl->getNodeByReference($ref);
                $args[] = $node !== null ? (string)$node : '';
            }
        } else {
            $args = array_values((array)$this->request->getPost('args', null, []));
        }
        if (count($args) > self::MAX_ARGS) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Too many arguments.')];
        }
        foreach ($args as $arg) {
            if (!is_string($arg) || !preg_match(self::ARG_TOKEN, $arg) || in_array('..', explode('/', $arg))) {
                return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid argument.')];
            }
        }
        if ($action == 'revert' && !preg_match(self::JOURNAL_ID, $args[0] ?? '')) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid journal id.')];
        }
        return array_merge([$action], $args);
    }

    /**
     * values of a settings revert may hold secrets, they never go to the browser
     */
    private function hideValues($result)
    {
        unset($result['values']);
        return $result;
    }
}
