"""
    Copyright (C) 2026 Igor Toledo <contato@igor.eti.br>
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.

    "Explain device" by the AI (text only): what the device probably is, why it got its risk, what to check and
    what to consider (isolate in an IoT network, block its internet access...) as suggestions. The first line of
    the answer carries the suggested type ("TYPE: camera"), stored as a suggestion next to the device; only the
    owner sets the type (change action devices_set). Modes: refresh | preview (what would be sent).
    The MAC address is reduced to its manufacturer prefix and the hostname is anonymised by the Assistant.
"""

import re

from . import common, store, view

INSTRUCTIONS = """You help the administrator of an OPNsense firewall understand ONE device of the local network.
The data comes from passive sources only (DHCP, ARP, host discovery, local DNS); the firmware version is unknown.
First line exactly "TYPE: <camera|nvr|tv|phone|pc|ap|iot|printer|console|unknown>" with your best guess.
Then, plain text, under 180 words:
What it probably is - and which signals support it (manufacturer, hostname, randomised MAC).
Risk - explain each risk reason in the data; say clearly that no vulnerability is confirmed without a version.
What to check - concrete checks for the owner (is it expected, firmware updates, default passwords).
Suggestions - e.g. move it to an isolated IoT network, block its internet access, remove a port forward. These are
suggestions for a human; nothing is changed automatically."""

TYPE_RE = re.compile(r'^\s*TYPE:\s*([a-z]+)', re.I | re.M)


def type_schema():
    """ Ollama structured output; rendered back to "TYPE: <type>" + text """
    return {'type': 'object',
            'properties': {'type': {'type': 'string', 'enum': list(common.TYPES)},
                           'explanation': {'type': 'string'}},
            'required': ['type', 'explanation']}


def render_type(doc):
    return 'TYPE: %s\n%s' % (doc.get('type') or 'unknown', str(doc.get('explanation') or '').strip())


def _ai():
    from ai import AIConfig, AIDisabled, Assistant, AuditLog, ProviderError, ProviderRefusal, Task
    return AIConfig, AIDisabled, Assistant, AuditLog, ProviderError, ProviderRefusal, Task


def device_data(dev):
    return {'manufacturer': dev['vendor'], 'oui_prefix': dev['mac'][:8], 'randomized_mac': dev['randomized'],
            'hostname': dev['hostname'], 'hostname_source': dev['hostname_source'],
            'interface': dev['iface_descr'], 'automatic_type': dev['auto_type'],
            'automatic_confidence': dev['auto_confidence'], 'automatic_why': dev['auto_why'],
            'owner_type': dev['user_type'], 'known_by_owner': dev['known'],
            'first_seen': dev['first_seen_iso'], 'last_seen': dev['last_seen_iso'], 'present_now': dev['present'],
            'risk': dev['risk'], 'risk_reasons': [r['text'] for r in dev['risk_reasons']],
            'addresses_seen': len(dev.get('addresses') or dev['ip4'])}


def explain(device_id, language='en_US', mode='refresh', assistant=None):
    AIConfig, AIDisabled, Assistant, AuditLog, ProviderError, ProviderRefusal, Task = _ai()
    detail = view.device(device_id)
    if detail.get('status') != 'ok':
        return detail
    dev = detail['device']
    language = common.valid_language(language)
    if assistant is None:
        config = AIConfig.from_opnsense(common.MOUNT, path=common.paths()['config'])
        assistant = Assistant(config, app='policyanalyzer', audit=AuditLog(common.AUDIT_LOG))
    task = Task('explain_device', INSTRUCTIONS, 'Explain this device of the local network.', schema=type_schema(),
                render=render_type, check_ctx={'first_values': list(common.TYPES)})
    data = device_data(dev)
    if mode == 'preview':
        result = assistant.preview(task, data, language)
        result['ai_enabled'] = bool(assistant.config.enabled)
        return result
    if not assistant.config.enabled:
        return {'status': 'disabled', 'message': 'AI assistance is disabled in the settings'}
    try:
        result = assistant.ask(task, data, language=language, subject='device:%d' % device_id)
    except AIDisabled as exc:
        return {'status': 'disabled', 'message': str(exc)}
    except (ProviderRefusal, ProviderError) as exc:
        return {'status': 'error', 'message': str(exc)}
    if result.get('status') == 'queued':
        return dict(result, device_id=device_id)
    text = (result.get('text') or '').strip()[:6000]
    match = TYPE_RE.search(text)
    suggested = match.group(1).lower() if match else 'unknown'
    if suggested not in common.TYPES:
        suggested = 'unknown'
    db = store.connect()
    try:
        old = store.get(db, device_id)
        db.execute('UPDATE devices SET ai_type = ?, ai_text = ?, ai_at = ? WHERE id = ?',
                   (suggested, text, int(common.now()), device_id))
        if old and old['ai_type'] != suggested:
            store.event(db, int(common.now()), device_id, 'ai', old['ai_type'], suggested, 'AI suggestion')
        db.commit()
    finally:
        db.close()
    return {'status': 'ok', 'text': text, 'suggested_type': suggested, 'model': result.get('model'),
            'provider': result.get('provider'), 'anonymized': result.get('anonymized'),
            'duration_ms': result.get('duration_ms'), 'device_id': device_id}
