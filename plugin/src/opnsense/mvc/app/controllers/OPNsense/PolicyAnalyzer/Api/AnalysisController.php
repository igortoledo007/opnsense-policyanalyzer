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
 * Analysis: run the (read-only) analyzer and browse its last report
 */
class AnalysisController extends ApiControllerBase
{
    use ApiHelperTrait;

    private const SEVERITY_RANK = ['high' => 0, 'medium' => 1, 'low' => 2, 'info' => 3];

    /**
     * run a new analysis, the report is stored by the backend in /var/db/policyanalyzer/last.json
     */
    public function analyzeAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        $report = $this->configdJson('policyanalyzer analyze', [], 600);
        if (!isset($report['findings'])) {
            return ['status' => 'error', 'message' => $report['message'] ?? \OPNsense\PolicyAnalyzer\L10n::t('Analysis failed.')];
        }
        return $this->reportHeader($report);
    }

    /**
     * full last report (contract version 1)
     */
    public function findingsAction()
    {
        $report = $this->configdJson('policyanalyzer findings');
        if (!isset($report['findings'])) {
            return ['status' => 'empty'];
        }
        return $report;
    }

    /**
     * report header only: summary, stats and the list of finding types, used by the cards and filters
     */
    public function summaryAction()
    {
        $report = $this->configdJson('policyanalyzer findings');
        if (!isset($report['findings'])) {
            return ['status' => 'empty'];
        }
        return $this->reportHeader($report);
    }

    /**
     * bootgrid search over the findings of the last report
     */
    public function searchAction()
    {
        $report = $this->configdJson('policyanalyzer findings');
        $rows = [];
        foreach ($report['findings'] ?? [] as $finding) {
            if (!is_array($finding) || !preg_match(self::FINDING_ID, $finding['id'] ?? '')) {
                continue;
            }
            $rules = [];
            $rules_text = [];
            foreach ($finding['rules'] ?? [] as $rule) {
                $rules[] = array_intersect_key($rule, array_flip([
                    'uuid', 'source', 'interface', 'direction', 'action', 'sequence', 'description', 'summary',
                    'quick', 'enabled', 'priority_group', 'ref'
                ]));
                $rules_text[] = ($rule['description'] ?? '') . ' ' . ($rule['summary'] ?? '');
            }
            $rows[] = [
                'id' => $finding['id'],
                'severity' => $finding['severity'] ?? 'info',
                'severity_rank' => self::SEVERITY_RANK[$finding['severity'] ?? 'info'] ?? 9,
                'type' => $finding['type'] ?? '',
                'title' => $finding['title'] ?? '',
                'recommendation' => $finding['recommendation'] ?? '',
                'rules' => $rules,
                'rules_text' => implode(' ', $rules_text),
                'aliases' => implode(', ', $finding['aliases'] ?? []),
            ];
        }
        $severities = (array)$this->request->getPost('severity', null, []);
        $types = (array)$this->request->getPost('type', null, []);
        $filter = function ($row) use ($severities, $types) {
            return (empty($severities) || in_array($row['severity'], $severities)) &&
                (empty($types) || in_array($row['type'], $types));
        };
        return $this->searchRecordsetBase(
            $rows,
            ['id', 'severity', 'type', 'title', 'recommendation', 'rules_text', 'aliases'],
            'severity_rank',
            $filter
        );
    }

    /**
     * one finding with its evidence
     * @param string $id finding id
     */
    public function findingAction($id = null)
    {
        if (!preg_match(self::FINDING_ID, (string)$id)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid finding id.')];
        }
        $report = $this->configdJson('policyanalyzer findings');
        foreach ($report['findings'] ?? [] as $finding) {
            if (($finding['id'] ?? '') === $id) {
                return ['status' => 'ok', 'finding' => $finding, 'generated' => $report['generated'] ?? null];
            }
        }
        return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Finding not found, run the analysis again.')];
    }

    private function reportHeader($report)
    {
        $types = [];
        foreach ($report['findings'] ?? [] as $finding) {
            if (!empty($finding['type'])) {
                $types[$finding['type']] = ($types[$finding['type']] ?? 0) + 1;
            }
        }
        ksort($types);
        return [
            'status' => 'ok',
            'version' => $report['version'] ?? null,
            'generated' => $report['generated'] ?? null,
            'duration_ms' => $report['duration_ms'] ?? null,
            'summary' => $report['summary'] ?? [],
            'stats_available' => $report['stats_available'] ?? false,
            'stats' => $report['stats'] ?? null,
            'types' => $types,
        ];
    }
}
