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


{# Firewall: Incidents: cases correlated from the IDS, the filter log, the quarantine and the DNS blocklist #}
<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/incidents.css') }}">
<script src="{{ cache_safe('/ui/js/policyanalyzer/simulation.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/aiqueue.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/incidents.js') }}"></script>
<script>
    'use strict';

    $(document).ready(function () {
        PASimulation.setStrings({
            simulate: "{{ lang._('Simulation') }}",
            nothing: "{{ lang._('Nothing to do: the system is already in the requested state.') }}",
            steps: "{{ lang._('Steps') }}",
            command: "{{ lang._('Command') }}",
            effect: "{{ lang._('Effect') }}",
            warnings: "{{ lang._('Warnings') }}",
            irreversible: "{{ lang._('Can not be reverted later') }}",
            revert: "{{ lang._('How to revert') }}",
            risk: "{{ lang._('Risk') }}",
            space: "{{ lang._('Disk space') }}",
            confirm: "{{ lang._('I reviewed the steps above and want to apply them.') }}",
            confirm2: "{{ lang._('I understand that part of this can not be undone or that other changes depend on it.') }}",
            apply: "{{ lang._('Apply') }}",
            close: "{{ lang._('Close') }}",
            cancel: "{{ lang._('Cancel') }}",
            done: "{{ lang._('Done') }}",
            failed: "{{ lang._('Failed') }}",
            completed: "{{ lang._('Completed steps') }}",
            journal: "{{ lang._('Recorded in the action history, it can be reverted from there.') }}",
            error: "{{ lang._('Error') }}",
            running: "{{ lang._('Running in the background') }}",
            technical: "{{ lang._('Technical details') }}",
            finished: "{{ lang._('Finished') }}",
            step: "{{ lang._('Step') }}"
        });
        PAIncidents.init({
            root: '#pa-incidents',
            strings: {
                title: "{{ lang._('Incidents') }}",
                notInstalled: "{{ lang._('Not installed') }}",
                installed: "{{ lang._('Correlating every 5 minutes') }}",
                noCron: "{{ lang._('installed, but the cron job is missing') }}",
                install: "{{ lang._('Install') }}",
                remove: "{{ lang._('Remove') }}",
                runNow: "{{ lang._('Run now') }}",
                refresh: "{{ lang._('Refresh') }}",
                digest: "{{ lang._('Daily digest') }}",
                lastRun: "{{ lang._('last run') }}",
                nextRun: "{{ lang._('next run') }}",
                never: "{{ lang._('never') }}",
                open: "{{ lang._('open') }}",
                new24h: "{{ lang._('new in 24 h') }}",
                active24h: "{{ lang._('active in 24 h') }}",
                installHelp: "{{ lang._('Installing creates the case database and a cron job every 5 minutes. The simulation shows every step first.') }}",
                sev_critical: "{{ lang._('Critical') }}",
                sev_high: "{{ lang._('High') }}",
                sev_medium: "{{ lang._('Medium') }}",
                sev_low: "{{ lang._('Low') }}",
                st_new: "{{ lang._('New') }}",
                st_investigating: "{{ lang._('In analysis') }}",
                st_resolved: "{{ lang._('Resolved') }}",
                st_false_positive: "{{ lang._('False positive') }}",
                st_open: "{{ lang._('Open (new + in analysis)') }}",
                any: "{{ lang._('any') }}",
                state: "{{ lang._('State') }}",
                severity: "{{ lang._('Severity') }}",
                rule: "{{ lang._('Rule') }}",
                period: "{{ lang._('Period') }}",
                search: "{{ lang._('Address, port or title') }}",
                apply: "{{ lang._('Apply') }}",
                clear: "{{ lang._('Clear') }}",
                filters: "{{ lang._('Filters') }}",
                d1: "{{ lang._('last 24 h') }}",
                d7: "{{ lang._('last 7 days') }}",
                d30: "{{ lang._('last 30 days') }}",
                d365: "{{ lang._('last year') }}",
                dall: "{{ lang._('all') }}",
                caseCol: "{{ lang._('Case') }}",
                entities: "{{ lang._('Entities') }}",
                lastActivity: "{{ lang._('Last activity') }}",
                score: "{{ lang._('Score') }}",
                noCases: "{{ lang._('No cases match the filters.') }}",
                selectCase: "{{ lang._('Select a case to see its timeline.') }}",
                prev: "{{ lang._('Previous') }}",
                next: "{{ lang._('Next') }}",
                page: "{{ lang._('page') }}",
                of: "{{ lang._('of') }}",
                r_scan_then_allowed: "{{ lang._('Scan then allowed') }}",
                r_ids_and_allowed: "{{ lang._('IDS + allowed traffic') }}",
                r_internal_to_bad: "{{ lang._('Internal host to bad destination') }}",
                r_campaign: "{{ lang._('Campaign') }}",
                r_repeat_offender: "{{ lang._('Repeat offender') }}",
                r_port_spike: "{{ lang._('Port spike') }}",
                k_ext: "{{ lang._('external') }}",
                k_int: "{{ lang._('internal') }}",
                k_own: "{{ lang._('firewall') }}",
                k_port: "{{ lang._('port') }}",
                k_rule: "{{ lang._('rule') }}",
                factors: "{{ lang._('Why this score') }}",
                timeline: "{{ lang._('Timeline') }}",
                notes: "{{ lang._('Notes') }}",
                history: "{{ lang._('History') }}",
                addNote: "{{ lang._('Add note') }}",
                notePlaceholder: "{{ lang._('What you checked, who you called, what you decided...') }}",
                changeState: "{{ lang._('Change state') }}",
                stateNote: "{{ lang._('Note (optional)') }}",
                confirm: "{{ lang._('Confirm') }}",
                cancel: "{{ lang._('Cancel') }}",
                close: "{{ lang._('Close') }}",
                summarize: "{{ lang._('Summarize with AI') }}",
                resummarize: "{{ lang._('Summarize again') }}",
                preview: "{{ lang._('Show what would be sent') }}",
                asking: "{{ lang._('Asking the AI, this can take a while...') }}",
                aiDisabled: "{{ lang._('AI assistance is disabled in the settings.') }}",
                aiSummary: "{{ lang._('AI summary') }}",
                hypothesis: "{{ lang._('Hypothesis') }}",
                impact: "{{ lang._('Impact') }}",
                nextSteps: "{{ lang._('Next steps') }}",
                confidence: "{{ lang._('confidence') }}",
                suggested: "{{ lang._('Suggested actions') }}",
                suggestedHelp: "{{ lang._('Each button opens the action with its simulation; nothing runs by itself.') }}",
                aiNote: "{{ lang._('Generated by the AI from the anonymized case. It may be wrong: check the timeline.') }}",
                quarantine: "{{ lang._('Quarantine') }}",
                quarantineFor: "{{ lang._('Put {ip} in quarantine') }}",
                duration: "{{ lang._('Duration') }}",
                liveView: "{{ lang._('Open in Live View') }}",
                copy: "{{ lang._('Copy') }}",
                inQuarantine: "{{ lang._('in quarantine') }}",
                level: "{{ lang._('level') }}",
                recently: "{{ lang._('quarantined recently') }}",
                first: "{{ lang._('first') }}",
                last: "{{ lang._('last') }}",
                count: "{{ lang._('count') }}",
                created: "{{ lang._('created') }}",
                state_changed: "{{ lang._('state') }}",
                log_created: "{{ lang._('Case created') }}",
                log_state: "{{ lang._('State changed') }}",
                log_note: "{{ lang._('Note') }}",
                log_summary: "{{ lang._('AI summary') }}",
                log_escalated: "{{ lang._('Severity raised') }}",
                previous: "{{ lang._('previous case') }}",
                suppressed: "{{ lang._('matches absorbed as false positive') }}",
                journal: "{{ lang._('Recorded in the action history, it can be reverted there.') }}",
                error: "{{ lang._('Error') }}",
                done: "{{ lang._('Done') }}",
                day: "{{ lang._('Day') }}",
                generate: "{{ lang._('Generate with AI') }}",
                regenerate: "{{ lang._('Generate again') }}",
                noDigest: "{{ lang._('No digest for this day yet.') }}",
                cases: "{{ lang._('cases') }}",
                newCases: "{{ lang._('new') }}",
                byRule: "{{ lang._('by rule') }}",
                topCases: "{{ lang._('Most relevant cases') }}",
                generatedAt: "{{ lang._('generated') }}",
                src_filter: "{{ lang._('filter') }}",
                src_suricata: "{{ lang._('IDS') }}",
                src_quarantine: "{{ lang._('quarantine') }}",
                src_dns: "{{ lang._('DNS') }}",
                src_engine: "{{ lang._('engine') }}",
                alsoMatched: "{{ lang._('Also matched') }}",
                f_recurrence: "{{ lang._('Recurrence') }}",
                f_contained: "{{ lang._('Already contained by the quarantine') }}",
                f_allowed_internal: "{{ lang._('Reached an internal host') }}",
                f_ids_sev1: "{{ lang._('IDS severity 1') }}",
                f_ids_sev2: "{{ lang._('IDS severity 2') }}",
                f_same_port: "{{ lang._('Allowed traffic on the port of the alert') }}",
                f_exposed: "{{ lang._('Internet reachable service involved') }}",
                f_allowed_to_bad: "{{ lang._('Traffic to a quarantined address was allowed') }}",
                f_active_quarantine: "{{ lang._('Destination in quarantine now') }}",
                f_dns: "{{ lang._('Blocked DNS queries') }}",
                f_volume: "{{ lang._('Event volume') }}",
                f_wide_scan: "{{ lang._('Wide port scan') }}",
                f_some_allowed: "{{ lang._('Part of it was allowed') }}",
                f_spike_ratio: "{{ lang._('Far above the usual hour') }}",
                f_level: "{{ lang._('High quarantine level') }}",
                evidenceMore: "{{ lang._('showing {n} of {total} evidence lines') }}",
                back: "{{ lang._('Back') }}",
                incidentComment: "{{ lang._('Incident #{id}') }}",
                ago_s: "{{ lang._('just now') }}",
                ago_m: "{{ lang._('{n} min ago') }}",
                ago_h: "{{ lang._('{n} h ago') }}",
                ago_d: "{{ lang._('{n} d ago') }}"
            }
        });
    });
</script>

<div class="content-box pa-i-page">
    <div id="pa-incidents" class="pa-i-root"></div>
</div>
