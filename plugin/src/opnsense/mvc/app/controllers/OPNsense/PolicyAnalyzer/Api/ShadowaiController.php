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
 * AI usage on the network (read only, configd pa_shadowai, see actions_pa_shadowai.conf):
 *   GET  report?days=7      the stored report (rebuilt when older than 15 minutes or for another window)
 *   POST run days=7        rebuild now
 *   GET  summary            light document for widgets (stored report, any age)
 *   GET  catalog            the merged AI service catalogue (shipped + local file)
 *   POST propose services=a,b scope=all|host|net value=<ip|cidr> method=unbound|alias [days]
 *                           blocking proposal + replay over the window; never applied
 *   POST explain target=overview|host [ip] [preview=1]
 */
class ShadowaiController extends ApiControllerBase
{
    use ApiHelperTrait;

    private const SERVICE_ID = '/^[a-z][a-z0-9_]{0,31}$/';

    private function days()
    {
        $days = (string)$this->request->get('days');
        return preg_match('/^[0-9]{1,2}$/', $days) && (int)$days >= 1 && (int)$days <= 30 ? $days : '7';
    }

    private function payload($data)
    {
        return rtrim(strtr(base64_encode(json_encode($data)), '+/', '-_'), '=');
    }

    public function reportAction()
    {
        return $this->configdJson('pa_shadowai last', [$this->days()], 90);
    }

    public function runAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        return $this->configdJson('pa_shadowai run', [$this->days()], 90);
    }

    public function summaryAction()
    {
        return $this->configdJson('pa_shadowai summary', [], 60);
    }

    public function catalogAction()
    {
        return $this->configdJson('pa_shadowai catalog', [], 30);
    }

    public function proposeAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        $services = [];
        foreach (explode(',', (string)$this->request->getPost('services')) as $sid) {
            $sid = trim($sid);
            if ($sid !== '' && preg_match(self::SERVICE_ID, $sid)) {
                $services[] = $sid;
            }
        }
        if (empty($services) || count($services) > 40) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Select at least one service.')];
        }
        $scope = (string)$this->request->getPost('scope');
        if (!in_array($scope, ['all', 'host', 'net'])) {
            $scope = 'all';
        }
        $value = trim((string)$this->request->getPost('value'));
        if ($scope == 'host' && filter_var($value, FILTER_VALIDATE_IP) === false) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid address.')];
        }
        if ($scope == 'net') {
            $parts = explode('/', $value);
            if (count($parts) != 2 || filter_var($parts[0], FILTER_VALIDATE_IP) === false ||
                !ctype_digit($parts[1]) || (int)$parts[1] > 128) {
                return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid network.')];
            }
        }
        $method = (string)$this->request->getPost('method') === 'alias' ? 'alias' : 'unbound';
        $payload = ['services' => $services, 'scope' => $scope, 'method' => $method,
                    'days' => (int)$this->days()];
        if ($scope != 'all') {
            $payload['value'] = $value;
        }
        return $this->configdJson('pa_shadowai propose', [$this->payload($payload)], 90);
    }

    public function explainAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        $target = (string)$this->request->getPost('target') === 'host' ? 'host' : 'overview';
        $payload = ['target' => $target, 'days' => (int)$this->days()];
        if ($target == 'host') {
            $ip = trim((string)$this->request->getPost('ip'));
            if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
                return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid address.')];
            }
            $payload['ip'] = $ip;
        }
        $preview = !empty($this->request->getPost('preview'));
        $mdl = $this->settings();
        if (!$preview && (empty((string)$mdl->ai->enabled) || (string)$mdl->ai->provider == 'none')) {
            return ['status' => 'disabled', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('AI assistance is disabled in the settings.')];
        }
        return $this->configdJson(
            'pa_shadowai explain',
            [$this->payload($payload), $this->aiLanguage(), $preview ? 'preview' : 'send'],
            $this->aiTimeout('shadowai_overview') + 60
        );
    }
}
