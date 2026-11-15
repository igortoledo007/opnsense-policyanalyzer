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
 * Reports and notification center (/api/policyanalyzer/reports/*), backend scripts/policyanalyzer/reports/.
 *
 *   GET  settings            settings (no secret), effective channel with the origin of each value, Monit view
 *   GET  monit               what "Import from Monit" would copy (never the password)
 *   GET  preview?kind=6h     report HTML + text, nothing sent or stored, without the AI
 *   POST preview {kind, ai}  same, ai=1 asks the AI for the executive summary
 *   GET  pdf?kind=manual     the report as PDF (application/pdf, attachment), same data as the e-mail, no AI
 *   POST pdf {kind, ai}      same, ai=1 asks the AI for the executive summary
 *   GET  history?page&rows&kind      e-mails sent / failed / skipped
 *   GET  message?id          one stored e-mail
 *   GET  notifications?page&rows&status   queue, history, subscriptions, sources
 *   GET  notifyPreview       what the detectors see now (nothing queued)
 *   POST resend {id}         queue a notification again and send it now
 *   GET  summary             light state for the Max Cyber
 *   POST plan|apply {action, args[]}  reports_settings, reports_import_monit, reports_send_test, revert
 */
class ReportsController extends ApiControllerBase
{
    use ApiHelperTrait;
    use ModuleHelperTrait;

    private const ACTIONS = ['reports_settings' => 1, 'reports_import_monit' => 0, 'reports_send_test' => 1,
                             'revert' => 2];

    public function settingsAction()
    {
        return $this->configdJson('pa_reports settings', [], 30);
    }

    public function monitAction()
    {
        return $this->configdJson('pa_reports monit', [], 30);
    }

    public function previewAction()
    {
        $kind = (string)$this->request->get('kind', null, 'manual');
        if (!in_array($kind, ['6h', 'daily', 'weekly', 'manual'], true)) {
            $kind = 'manual';
        }
        $ai = $this->request->isPost() && $this->request->getPost('ai') === '1';
        return $this->configdJson('pa_reports preview', [$kind, $ai ? 'ai' : '-'], $ai ? $this->aiTimeout('report_summary') + 90 : 120);
    }

    /**
     * download the report PDF: configd answers text, so the backend sends the PDF base64 encoded inside its JSON
     * (cli.py preview <kind> pdf|aipdf) and it is decoded here and served as a binary attachment
     */
    public function pdfAction()
    {
        $kind = (string)$this->request->get('kind', null, 'manual');
        if (!in_array($kind, ['6h', 'daily', 'weekly', 'manual'], true)) {
            $kind = 'manual';
        }
        $ai = $this->request->isPost() && $this->request->getPost('ai') === '1';
        $data = $this->configdJson('pa_reports preview', [$kind, $ai ? 'aipdf' : 'pdf'],
            $ai ? $this->aiTimeout('report_summary') + 90 : 120);
        if (($data['status'] ?? '') !== 'ok' || empty($data['pdf'])) {
            return ['status' => 'error', 'message' => $data['message'] ?? \OPNsense\PolicyAnalyzer\L10n::t('Unable to build the PDF.')];
        }
        $pdf = base64_decode((string)$data['pdf'], true);
        if ($pdf === false || substr($pdf, 0, 5) !== '%PDF-') {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Unexpected answer from the backend.')];
        }
        $name = (string)($data['name'] ?? '');
        if (!preg_match('/^opnsense-relatorio-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4}\.pdf$/', $name)) {
            $name = 'opnsense-relatorio.pdf';
        }
        $this->response->setContentType('application/pdf');
        $this->response->setHeader('Content-Disposition', 'attachment; filename="' . $name . '"');
        $this->response->setHeader('Content-Length', (string)strlen($pdf));
        $this->response->setHeader('Cache-Control', 'no-store');
        $this->response->setHeader('X-Content-Type-Options', 'nosniff');
        $this->response->setContent($pdf);
    }

    public function historyAction()
    {
        $kind = (string)$this->request->get('kind', null, '');
        $kind = in_array($kind, ['report', 'test', 'notification', 'digest'], true) ? $kind : '-';
        return $this->configdJson('pa_reports history', [$this->pageToken(25), $kind], 30);
    }

    public function messageAction()
    {
        $id = (string)$this->request->get('id', null, '');
        if (!preg_match('/^[0-9]{1,9}$/', $id)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid id.')];
        }
        return $this->configdJson('pa_reports message', [$id], 30);
    }

    public function notificationsAction()
    {
        $status = (string)$this->request->get('status', null, '');
        $status = in_array($status, ['queued', 'held', 'sent', 'failed', 'suppressed'], true) ? $status : '-';
        return $this->configdJson('pa_reports notifications', [$this->pageToken(50), $status], 30);
    }

    public function notifyPreviewAction()
    {
        return $this->configdJson('pa_reports notify_preview', [], 120);
    }

    public function resendAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('POST required')];
        }
        $id = (string)$this->request->getPost('id');
        if (!preg_match('/^[0-9]{1,9}$/', $id)) {
            return ['status' => 'error', 'message' => \OPNsense\PolicyAnalyzer\L10n::t('Invalid id.')];
        }
        $this->throwReadOnly();
        return $this->configdJson('pa_reports resend', [$id], $this->aiTimeout('report_summary') + 90);
    }

    public function summaryAction()
    {
        return $this->configdJson('pa_reports summary', [], 30);
    }

    public function planAction()
    {
        return $this->moduleChange('pa_reports', self::ACTIONS, 'plan');
    }

    public function applyAction()
    {
        return $this->moduleChange('pa_reports', self::ACTIONS, 'apply');
    }
}
