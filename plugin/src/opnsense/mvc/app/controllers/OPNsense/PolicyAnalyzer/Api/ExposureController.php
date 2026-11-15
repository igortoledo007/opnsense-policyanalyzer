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
 * Exposure & vulnerabilities (read only): the last stored report and a fresh offline run.
 * The Sonar widget (Max Cyber) reads report.
 */
class ExposureController extends ApiControllerBase
{
    use ApiHelperTrait;

    /**
     * last stored report (/var/db/policyanalyzer/exposure.json); runs an offline report when none exists yet
     */
    public function reportAction()
    {
        $data = $this->configdJson('policyanalyzer exposure_last', [], 15);
        if (($data['status'] ?? '') === 'error') {
            $data = $this->configdJson('policyanalyzer exposure_report', ['offline'], 120);
        }
        return $data;
    }

    /**
     * new report; online=1 enriches with the configured feeds (only CVE ids leave the firewall)
     */
    public function runAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $online = $this->request->getPost('online') === '1';
        return $this->configdJson('policyanalyzer exposure_report', [$online ? 'online' : 'offline'], 300);
    }
}
