{#
 # Copyright (C) 2026 Igor Toledo <contato@igor.eti.br>
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without
 # modification, are permitted provided that the following conditions are met:
 #
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 #
 # 2. Redistributions in binary form must reproduce the above copyright
 #    notice, this list of conditions and the following disclaimer in the
 #    documentation and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 #}

{#
 # Reports and notification center (body): used by reports.volt (page /ui/policyanalyzer/reports) and, once
 # index.volt includes it, as a tab of the Policy Analyzer page (partial OPNsense/PolicyAnalyzer/reports_body).
 # JS: reports.js. The strings block below is generated from PAReports.DEFAULTS and the PAMod defaults.
 #}
<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/modules.css') }}">
<script src="{{ cache_safe('/ui/js/policyanalyzer/modules.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/reports.js') }}"></script>
<script>
    'use strict';
    $(document).ready(function () {
        PAMod.setStrings({
            loading: "{{ lang._('Loading...') }}",
            error: "{{ lang._('Error') }}",
            none: "{{ lang._('Nothing to show.') }}",
            close: "{{ lang._('Close') }}",
            preview: "{{ lang._('Show what is sent') }}",
            ask: "{{ lang._('Ask the AI') }}",
            asking: "{{ lang._('Asking the AI... (it may take a while)') }}",
            aiOff: "{{ lang._('The AI is disabled in the Policy Analyzer settings.') }}",
            aiNote: "{{ lang._('The AI only explains and suggests: nothing is changed. Apply any change yourself, with its simulation.') }}",
            payloadTitle: "{{ lang._('Exactly what would be sent (anonymised when the option is on)') }}",
            model: "{{ lang._('Model') }}",
            cached: "{{ lang._('Stored answer from') }}",
            never: "{{ lang._('never') }}"
        });
        PAReports.setStrings({
            title: "{{ lang._('Reports and notifications') }}",
            subtitle: "{{ lang._('Security report every 6 h / daily and e-mail alerts, through the e-mail setup of Monit.') }}",
            refresh: "{{ lang._('Refresh') }}",
            tabChannel: "{{ lang._('E-mail channel') }}",
            tabReports: "{{ lang._('Periodic report') }}",
            tabNotify: "{{ lang._('Notifications') }}",
            tabHistory: "{{ lang._('Sent e-mails') }}",
            modeMonit: "{{ lang._('Use Monit settings') }}",
            modeMonitHelp: "{{ lang._('Server, port, TLS, user, password, sender and recipients are read from Services > Monit at every send: always in sync, nothing is copied.') }}",
            modeOwn: "{{ lang._('Own settings (imported from Monit or typed)') }}",
            modeOwnHelp: "{{ lang._('Independent copy, editable here. The password is kept as a masked secret and never shown.') }}",
            active: "{{ lang._('Active') }}",
            origin: "{{ lang._('Origin') }}",
            field: "{{ lang._('Field') }}",
            value: "{{ lang._('Value') }}",
            host: "{{ lang._('SMTP server') }}",
            port: "{{ lang._('Port') }}",
            security: "{{ lang._('Security') }}",
            verify: "{{ lang._('Verify certificate') }}",
            minTls: "{{ lang._('Minimum TLS') }}",
            username: "{{ lang._('User') }}",
            password: "{{ lang._('Password') }}",
            passwordKeep: "{{ lang._('empty: keep %s') }}",
            passwordNone: "{{ lang._('empty: no password') }}",
            sender: "{{ lang._('Sender') }}",
            recipients: "{{ lang._('Recipients') }}",
            recipientsHelp: "{{ lang._('Comma separated') }}",
            recipientsMonit: "{{ lang._('Recipients (empty: the Monit alert recipients)') }}",
            monitMissing: "{{ lang._('Monit has no mail server configured (Services > Monit > Settings).') }}",
            channelBroken: "{{ lang._('The channel is not usable yet: %s') }}",
            saveChannel: "{{ lang._('Save channel') }}",
            importMonit: "{{ lang._('Import from Monit') }}",
            importTitle: "{{ lang._('Import the Monit e-mail settings') }}",
            sendTest: "{{ lang._('Send test') }}",
            sendTestTitle: "{{ lang._('Send a test e-mail') }}",
            saveTitle: "{{ lang._('Save reports and notifications settings') }}",
            repEnabled: "{{ lang._('Send the periodic report') }}",
            every6h: "{{ lang._('Every 6 hours') }}",
            daily: "{{ lang._('Daily at') }}",
            onlyEvents: "{{ lang._('Every 6 h only when something happened') }}",
            aiSummary: "{{ lang._('Executive summary by the AI (fixed text when the AI is off)') }}",
            language: "{{ lang._('Language') }}",
            attachPdf: "{{ lang._('Attach the report as PDF') }}",
            downloadPdf: "{{ lang._('Download PDF') }}",
            pdfError: "{{ lang._('Unable to build the PDF.') }}",
            sections: "{{ lang._('Sections') }}",
            sec_posture: "{{ lang._('Posture (exposure)') }}",
            sec_quarantine: "{{ lang._('Quarantine') }}",
            sec_findings: "{{ lang._('Policy Analyzer findings') }}",
            sec_traffic: "{{ lang._('Top blocks, ports and countries') }}",
            sec_cves: "{{ lang._('Relevant CVEs') }}",
            sec_devices: "{{ lang._('Devices') }}",
            sec_notifications: "{{ lang._('Notifications sent') }}",
            sec_ai_summary: "{{ lang._('AI executive summary') }}",
            saveReports: "{{ lang._('Save report settings') }}",
            preview: "{{ lang._('Preview') }}",
            previewAi: "{{ lang._('Preview with AI summary') }}",
            sendNow: "{{ lang._('Send report now') }}",
            sendNowTitle: "{{ lang._('Send the report now') }}",
            htmlView: "{{ lang._('HTML') }}",
            textView: "{{ lang._('Text') }}",
            cronState: "{{ lang._('Scheduled jobs (System > Settings > Cron)') }}",
            cronNone: "{{ lang._('none') }}",
            cronPending: "{{ lang._('saving will change the jobs') }}",
            notifyEnabled: "{{ lang._('Notification center enabled') }}",
            notifyOn: "{{ lang._('enabled') }}",
            notifyOff: "{{ lang._('disabled') }}",
            lastRun: "{{ lang._('last run %s') }}",
            colEvent: "{{ lang._('Event') }}",
            colSource: "{{ lang._('Source') }}",
            colSubscribe: "{{ lang._('Subscribe') }}",
            colMinSev: "{{ lang._('Minimum severity') }}",
            colThrottle: "{{ lang._('Throttle (min)') }}",
            unavailable: "{{ lang._('module not installed') }}",
            maxPerHour: "{{ lang._('At most e-mails per hour') }}",
            notifyAi: "{{ lang._('Short AI summary in each alert (fixed text when the AI is off)') }}",
            saveNotify: "{{ lang._('Save notification settings') }}",
            checkSources: "{{ lang._('Check sources now') }}",
            sourcesTitle: "{{ lang._('What the sources see now (nothing is queued or sent)') }}",
            queue: "{{ lang._('Queue and history') }}",
            allStatus: "{{ lang._('All') }}",
            st_queued: "{{ lang._('queued') }}",
            st_held: "{{ lang._('held (throttle)') }}",
            st_sent: "{{ lang._('sent') }}",
            st_failed: "{{ lang._('failed') }}",
            st_suppressed: "{{ lang._('suppressed') }}",
            colWhen: "{{ lang._('When') }}",
            colType: "{{ lang._('Type') }}",
            colSev: "{{ lang._('Severity') }}",
            colTitle: "{{ lang._('Title') }}",
            colStatus: "{{ lang._('Status') }}",
            colActions: "{{ lang._('Actions') }}",
            resend: "{{ lang._('Resend') }}",
            resendConfirm: "{{ lang._('Send this notification again now (an e-mail can not be unsent)?') }}",
            open: "{{ lang._('Open') }}",
            colSubject: "{{ lang._('Subject') }}",
            colTo: "{{ lang._('To') }}",
            colKind: "{{ lang._('Kind') }}",
            colAi: "{{ lang._('AI') }}",
            view: "{{ lang._('View') }}",
            throttleHelp: "{{ lang._('Events of the same type inside the throttle window are grouped into one digest e-mail.') }}",
            events: "{{ lang._('events') }}",
            none: "{{ lang._('none') }}"
        });
        PAReports.init();
    });
</script>

<div id="pa_reports" class="pa-mod">
    <div class="pa-mod-head">
        <div>
            <h2><i class="fa fa-envelope-o"></i> {{ lang._('Reports and notifications') }}</h2>
            <div class="pa-mod-sub">{{ lang._('Security report every 6 h / daily and e-mail alerts, through the e-mail setup of Monit.') }}</div>
        </div>
        <div class="pa-mod-actions">
            <a class="btn btn-default btn-sm" href="/ui/monit"><i class="fa fa-heartbeat"></i> Monit</a>
            <button type="button" class="btn btn-default btn-sm" id="par_refresh"><i class="fa fa-refresh"></i> {{ lang._('Refresh') }}</button>
        </div>
    </div>
    <ul class="nav nav-tabs" role="tablist">
        <li class="active"><a data-toggle="tab" href="#par_tab_channel">{{ lang._('E-mail channel') }}</a></li>
        <li><a data-toggle="tab" href="#par_tab_reports">{{ lang._('Periodic report') }}</a></li>
        <li><a data-toggle="tab" href="#par_tab_notifications">{{ lang._('Notifications') }}</a></li>
        <li><a data-toggle="tab" href="#par_tab_history">{{ lang._('Sent e-mails') }}</a></li>
    </ul>
    <div class="tab-content">
        <div id="par_tab_channel" class="tab-pane fade in active"><div id="par_channel"></div></div>
        <div id="par_tab_reports" class="tab-pane fade"><div id="par_reports"></div></div>
        <div id="par_tab_notifications" class="tab-pane fade">
            <div id="par_notify"></div>
            <div id="par_queue" style="margin-top:10px"></div>
        </div>
        <div id="par_tab_history" class="tab-pane fade"><div id="par_history"></div></div>
    </div>
    <p class="pa-small" style="padding:8px 12px 0">{{ lang._('The AI only summarises and recommends. Saving, importing and sending always show a simulation first; saved settings are recorded in the action history of the Policy Analyzer and can be reverted there. The Monit password is never shown, copied to the browser or written to a log.') }}</p>
</div>
