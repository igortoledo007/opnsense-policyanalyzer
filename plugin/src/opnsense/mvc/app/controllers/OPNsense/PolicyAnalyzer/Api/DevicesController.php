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
 * Passive LAN device inventory (/api/policyanalyzer/devices/*), backend scripts/policyanalyzer/devices/.
 *
 *   GET  summary                   light counts (Max Cyber, reports); scans when the last scan is old
 *   GET  list?type&risk&known&present&new&search&sort&page&rows
 *   GET  device?id=                one device with addresses and history
 *   GET  oui                       manufacturer database in use
 *   POST scan                      passive scan now (writes only devices.db)
 *   POST explain {id, mode: refresh|preview}
 *   POST plan|apply {action, args[]}  devices_mark_known, devices_set, devices_oui_update, revert
 */
class DevicesController extends ApiControllerBase
{
    use ApiHelperTrait;
    use ModuleHelperTrait;

    private const ACTIONS = ['devices_mark_known' => 2, 'devices_set' => 3, 'devices_oui_update' => 0, 'revert' => 2];
    private const FILTERS = ['type' => '/^[a-z]{2,10}$/', 'risk' => '/^(high|medium|low|info)$/',
                             'known' => '/^[01]$/', 'present' => '/^[01]$/', 'new' => '/^[01]$/'];

    public function summaryAction()
    {
        return $this->configdJson('pa_devices summary', [], 90);
    }

    public function listAction()
    {
        $filters = [];
        foreach (self::FILTERS as $key => $regex) {
            $value = (string)$this->request->get($key, null, '');
            if ($value !== '' && preg_match($regex, $value)) {
                $filters[] = $key . '=' . $value;
            }
        }
        $search = trim((string)$this->request->get('search', null, ''));
        if ($search !== '' && preg_match('/^[0-9A-Za-z:._ -]{1,64}$/', $search)) {
            $filters[] = 'search=' . str_replace(' ', '_', $search);
        }
        $sort = (string)$this->request->get('sort', null, 'risk');
        $sort = in_array($sort, ['risk', 'last_seen', 'first_seen', 'name', 'type'], true) ? $sort : 'risk';
        return $this->configdJson('pa_devices list', [empty($filters) ? '-' : implode('+', $filters), $sort,
                                                      $this->pageToken(50)], 90);
    }

    public function deviceAction()
    {
        $id = (string)$this->request->get('id', null, '');
        if (!preg_match('/^[0-9]{1,9}$/', $id)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid id.')];
        }
        return $this->configdJson('pa_devices device', [$id], 30);
    }

    public function ouiAction()
    {
        return $this->configdJson('pa_devices oui', [], 30);
    }

    public function scanAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        return $this->configdJson('pa_devices scan', [], 120);
    }

    public function explainAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        $id = (string)$this->request->getPost('id');
        if (!preg_match('/^[0-9]{1,9}$/', $id)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid id.')];
        }
        $mode = $this->request->getPost('mode') === 'preview' ? 'preview' : 'refresh';
        return $this->configdJson('pa_devices explain', [$id, $this->aiLanguage(), $mode],
            $mode === 'refresh' ? $this->aiTimeout('explain_device') + 30 : 60);
    }

    public function planAction()
    {
        return $this->moduleChange('pa_devices', self::ACTIONS, 'plan');
    }

    public function applyAction()
    {
        return $this->moduleChange('pa_devices', self::ACTIONS, 'apply');
    }
}
