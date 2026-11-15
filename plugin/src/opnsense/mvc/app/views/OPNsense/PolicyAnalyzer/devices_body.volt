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
 # Devices (body): used by devices.volt (page /ui/policyanalyzer/devices) and, once index.volt includes it, as a
 # tab of the Policy Analyzer page (partial OPNsense/PolicyAnalyzer/devices_body). JS: devices.js.
 # The strings block below is generated from PADevices.DEFAULTS and the PAMod defaults (same keys, translated).
 #}
<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/modules.css') }}">
<script src="{{ cache_safe('/ui/js/policyanalyzer/modules.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/devices.js') }}"></script>
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
        PADevices.setStrings({
            title: "{{ lang._('Devices') }}",
            subtitle: "{{ lang._('Passive inventory of the local network: nothing is sent to the devices.') }}",
            scan: "{{ lang._('Scan now') }}",
            refresh: "{{ lang._('Refresh') }}",
            updateOui: "{{ lang._('Update manufacturer database') }}",
            updateOuiTitle: "{{ lang._('Download the IEEE OUI registry') }}",
            kpiTotal: "{{ lang._('Devices') }}",
            kpiPresent: "{{ lang._('Present now') }}",
            kpiNew: "{{ lang._('New (7 days)') }}",
            kpiUnknown: "{{ lang._('Not marked known') }}",
            kpiHigh: "{{ lang._('High risk') }}",
            kpiMedium: "{{ lang._('Medium risk') }}",
            lastScan: "{{ lang._('Last scan %s') }}",
            ouiSource: "{{ lang._('Manufacturers: %s (%s entries)') }}",
            sources: "{{ lang._('Sources') }}",
            allTypes: "{{ lang._('All types') }}",
            allRisks: "{{ lang._('All risks') }}",
            onlyNew: "{{ lang._('New') }}",
            onlyUnknown: "{{ lang._('Not known') }}",
            onlyPresent: "{{ lang._('Present') }}",
            search: "{{ lang._('Search name, vendor, IP, MAC') }}",
            markKnown: "{{ lang._('Mark as known') }}",
            markUnknown: "{{ lang._('Mark as not known') }}",
            markTitle: "{{ lang._('Mark %s device(s)') }}",
            selected: "{{ lang._('%s selected') }}",
            colName: "{{ lang._('Name') }}",
            colType: "{{ lang._('Type') }}",
            colVendor: "{{ lang._('Manufacturer') }}",
            colIp: "{{ lang._('Address') }}",
            colIface: "{{ lang._('Interface') }}",
            colFirst: "{{ lang._('First seen') }}",
            colLast: "{{ lang._('Last seen') }}",
            colRisk: "{{ lang._('Risk') }}",
            colActions: "{{ lang._('Actions') }}",
            explain: "{{ lang._('Explain') }}",
            explainTitle: "{{ lang._('Explain device %s') }}",
            edit: "{{ lang._('Edit') }}",
            editTitle: "{{ lang._('Type and name of %s') }}",
            history: "{{ lang._('History') }}",
            historyTitle: "{{ lang._('History of %s') }}",
            known: "{{ lang._('known') }}",
            new: "{{ lang._('new') }}",
            present: "{{ lang._('present') }}",
            heuristic: "{{ lang._('automatic') }}",
            owner: "{{ lang._('set by you') }}",
            aiSuggests: "{{ lang._('AI suggests %s') }}",
            typeAuto: "{{ lang._('Automatic (%s)') }}",
            name: "{{ lang._('Name') }}",
            nameHelp: "{{ lang._('Empty: the hostname seen on the network') }}",
            simulate: "{{ lang._('Simulate') }}",
            why: "{{ lang._('Why this type') }}",
            riskWhy: "{{ lang._('Why this risk') }}",
            randomMac: "{{ lang._('random MAC') }}",
            addresses: "{{ lang._('Addresses') }}",
            events: "{{ lang._('Events') }}",
            mac: "{{ lang._('MAC') }}",
            type_camera: "{{ lang._('camera') }}",
            type_nvr: "{{ lang._('NVR/DVR') }}",
            type_tv: "{{ lang._('TV') }}",
            type_phone: "{{ lang._('phone') }}",
            type_pc: "{{ lang._('computer') }}",
            type_ap: "{{ lang._('AP/router') }}",
            type_iot: "{{ lang._('IoT') }}",
            type_printer: "{{ lang._('printer') }}",
            type_console: "{{ lang._('console') }}",
            type_unknown: "{{ lang._('unknown') }}",
            risk_high: "{{ lang._('high') }}",
            risk_medium: "{{ lang._('medium') }}",
            risk_low: "{{ lang._('low') }}",
            risk_info: "{{ lang._('info') }}",
            noScan: "{{ lang._('No scan yet: click Scan now.') }}"
        });
        PADevices.init();
    });
</script>

<div id="pa_devices" class="pa-mod">
    <div class="pa-mod-head">
        <div>
            <h2><i class="fa fa-sitemap"></i> {{ lang._('Devices') }}</h2>
            <div class="pa-mod-sub">{{ lang._('Passive inventory of the local network: nothing is sent to the devices.') }}</div>
        </div>
        <div class="pa-mod-actions">
            <button type="button" class="btn btn-default btn-sm" id="pad_refresh"><i class="fa fa-refresh"></i> {{ lang._('Refresh') }}</button>
            <button type="button" class="btn btn-primary btn-sm" id="pad_scan"><i class="fa fa-search"></i> {{ lang._('Scan now') }}</button>
        </div>
    </div>
    <div class="pa-mod-kpis" id="pad_kpis"></div>
    <div class="pa-mod-note" id="pad_meta"></div>
    <div style="padding:0 12px">
        <div class="pa-mod-toolbar">
            <select class="form-control" id="pad_type" aria-label="{{ lang._('Type') }}"><option value="">{{ lang._('All types') }}</option></select>
            <select class="form-control" id="pad_risk" aria-label="{{ lang._('Risk') }}">
                <option value="">{{ lang._('All risks') }}</option><option value="high">{{ lang._('high') }}</option>
                <option value="medium">{{ lang._('medium') }}</option><option value="low">{{ lang._('low') }}</option>
                <option value="info">{{ lang._('info') }}</option>
            </select>
            <label class="checkbox-inline"><input type="checkbox" id="pad_new"> {{ lang._('New') }}</label>
            <label class="checkbox-inline"><input type="checkbox" id="pad_unknown"> {{ lang._('Not known') }}</label>
            <label class="checkbox-inline"><input type="checkbox" id="pad_present"> {{ lang._('Present') }}</label>
            <input type="search" class="form-control pa-right" id="pad_search" placeholder="{{ lang._('Search name, vendor, IP, MAC') }}">
        </div>
        <div class="pa-mod-toolbar" id="pad_batch" style="display:none">
            <b id="pad_batch_n"></b>
            <button type="button" class="btn btn-xs btn-primary pa-batch-known" data-known="1">{{ lang._('Mark as known') }}</button>
            <button type="button" class="btn btn-xs btn-default pa-batch-known" data-known="0">{{ lang._('Mark as not known') }}</button>
        </div>
        <div class="pa-scroll" id="pad_table"></div>
        <p class="pa-small" style="margin-top:6px">{{ lang._('Risk is inferred without the firmware version (manufacturer history, CISA KEV entries of the manufacturer, port forwards, new device): it is a hint, never a confirmed vulnerability. Isolating a device is a suggestion of the AI; do it yourself in Firewall > Rules.') }}</p>
    </div>
</div>
