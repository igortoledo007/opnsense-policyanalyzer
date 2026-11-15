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
 * AI layer: explanations (text only, never applied), provider registry, connection test and model list.
 * Nothing here changes the configuration; storage preparation goes through ChangeController (plan/apply).
 */
class AiController extends ApiControllerBase
{
    use ApiHelperTrait;

    /**
     * state used by the page to decide whether "Explain with AI" is offered
     */
    public function statusAction()
    {
        $mdl = $this->settings();
        $provider = (string)$mdl->ai->provider;
        $enabled = !empty((string)$mdl->ai->enabled) && $provider != 'none';
        $model = '';
        if ($provider != 'none' && isset($mdl->$provider) && isset($mdl->$provider->model)) {
            $model = (string)$mdl->$provider->model;
        }
        return [
            'status' => 'ok',
            'enabled' => $enabled,
            'provider' => $provider,
            'model' => $model,
            'anonymize' => !empty((string)$mdl->ai->anonymize),
            'language' => $this->aiLanguage(),
        ];
    }

    /**
     * provider registry (choices grouped local/api, fields, privacy notes) from the backend
     */
    public function providersAction()
    {
        return $this->configdJson('policyanalyzer ai_providers');
    }

    /**
     * explain one finding ("id") or the whole report ("all"); preview=1 returns the payload without sending it
     */
    public function explainAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        $id = (string)$this->request->getPost('id');
        if ($id !== 'all' && !preg_match(self::FINDING_ID, $id)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid finding id.')];
        }
        $preview = !empty($this->request->getPost('preview'));
        $mdl = $this->settings();
        if (!$preview && (empty((string)$mdl->ai->enabled) || (string)$mdl->ai->provider == 'none')) {
            return ['status' => 'disabled', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('AI assistance is disabled in the settings.')];
        }
        $timeout = $this->aiTimeout($id === 'all' ? 'explain_set' : 'explain_finding') + 30;
        return $this->configdJson(
            'policyanalyzer explain',
            [$id, $this->aiLanguage(), $preview ? 'preview' : 'send'],
            $timeout
        );
    }

    /**
     * situational brief for the Max Cyber war room (read only, text):
     *   GET              the stored brief (mode=cached, fast, never calls the AI)
     *   POST mode=refresh  starts a background generation when the stored one is older than 10 min, returns
     *                    the current state at once (status running while the detached job works)
     * focus=<ip> (optional) asks about one remote address instead of the general picture.
     */
    public function briefAction()
    {
        $mode = 'cached';
        if ($this->request->isPost()) {
            $mode = (string)$this->request->getPost('mode') === 'cached' ? 'cached' : 'refresh';
        }
        $focus = trim((string)$this->request->get('focus'));
        if ($focus !== '' && filter_var($focus, FILTER_VALIDATE_IP) === false) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid address.')];
        }
        $mdl = $this->settings();
        if (empty((string)$mdl->ai->enabled) || (string)$mdl->ai->provider == 'none') {
            return [
                'status' => 'disabled',
                'focus' => $focus !== '' ? $focus : null,
                'message' => \OPNsense\PolicyAnalyzer\L10n::t('AI assistance is disabled in the settings.'),
            ];
        }
        return $this->configdJson(
            'policyanalyzer ai_brief',
            [$mode, $this->aiLanguage(), $focus !== '' ? $focus : '-'],
            30
        );
    }

    /**
     * reachability, version and model availability of the saved provider settings (no user data is sent)
     */
    public function testAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        return $this->configdJson('policyanalyzer ai_test', [], $this->aiTimeout() + 15);
    }

    /**
     * models offered by the saved provider (Ollama /api/tags, Anthropic /v1/models)
     */
    public function modelsAction()
    {
        return $this->configdJson('policyanalyzer ai_models', [], 60);
    }

    /**
     * read-only probe of the local runtime (jail, Ollama version, listeners, models, limits)
     */
    public function runtimeAction()
    {
        return $this->configdJson('policyanalyzer ai_runtime', [], 30);
    }

    /**
     * models that fit this hardware (recommended model, alternatives with verdicts, suggested num_thread/num_ctx)
     */
    public function recommendAction()
    {
        /* RAM budget in percent: request value (live, before saving) or the saved setting */
        $budget = (string)$this->request->get('budget');
        if (!preg_match('/^[0-9]{1,2}$/', $budget) || (int)$budget < 10 || (int)$budget > 75) {
            $budget = (string)$this->settings()->ollama->ram_budget;
        }
        return $this->configdJson('policyanalyzer ai_recommend', [$budget], 60);
    }

    /**
     * hardware profile (CPU, RAM in use, GPUs, heavy services) of this firewall
     */
    public function hwProfileAction()
    {
        return $this->configdJson('policyanalyzer ai_hw_profile', [], 60);
    }

    /**
     * progress of the running (or last) background setup job, polled while a change reports "started"
     */
    public function jobAction()
    {
        return $this->configdJson('policyanalyzer setup_job', [], 15);
    }

    /**
     * AI per scenario: catalog, presets, fallback and the resolved route of every scenario (read only; changes go
     * through ChangeController with the actions ai_routing and ai_queue_schedule)
     */
    public function routingAction()
    {
        return $this->configdJson('policyanalyzer ai_routing', [], 30);
    }

    /**
     * background AI queue: latest jobs (status, position, estimate, times, tokens, model, format/language checks),
     * statistics per scenario and model, worker state
     */
    public function queueAction()
    {
        $limit = (string)$this->request->get('limit');
        if (!preg_match('/^[0-9]{1,3}$/', $limit)) {
            $limit = '50';
        }
        return $this->configdJson('policyanalyzer ai_queue', [$limit], 30);
    }

    /**
     * one job of the AI queue: position and estimate while queued, the module result once finished (polled by
     * the pages while a request answered "queued")
     */
    public function queueJobAction()
    {
        $id = (string)$this->request->get('id');
        if (!preg_match('/^[0-9]{1,10}$/', $id)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid job id.')];
        }
        return $this->configdJson('policyanalyzer ai_queue_job', [$id], 30);
    }

    /**
     * start the queue worker now (it also starts on demand and from the cron job)
     */
    public function queueKickAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        return $this->configdJson('policyanalyzer ai_queue_kick', [], 30);
    }

    /**
     * cancel a queued (or stop a running) AI job; nothing else changes
     */
    public function queueCancelAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        $id = (string)$this->request->getPost('id');
        if (!preg_match('/^[0-9]{1,10}$/', $id)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid job id.')];
        }
        return $this->configdJson('policyanalyzer ai_queue_cancel', [$id], 30);
    }

    /**
     * read-only probe of the local models directory: exists, writable, filesystem, dataset, free space
     */
    public function storageAction()
    {
        $path = (string)$this->request->get('path');
        if ($path === '') {
            $path = (string)$this->settings()->ollama->models_dir;
        }
        if (!preg_match('/^\/[A-Za-z0-9._\/-]{0,254}$/', $path) || in_array('..', explode('/', $path))) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid path.')];
        }
        return $this->configdJson('policyanalyzer ai_storage', [$path], 30);
    }
}
