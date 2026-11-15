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

    Change actions of the vulnerabilities (plan / apply / revert, journal in /var/db/policyanalyzer/undo/):

      vulns_intel_update <kev|epss|all>                    download KEV and/or EPSS into the local cache (network,
                                                            only CVE ids are sent to EPSS); revert restores the
                                                            previous cache files
      vulns_review_decide <item id> <decision> <comment>   decision on an item of the review queue
                                                            (map:<service id> | none | ignore[=days] | finding |
                                                            clear); the plan shows how the priorities change;
                                                            revert restores the previous decision

    Neither touches config.xml, rules or services of the firewall: only files of the plugin below
    /var/db/policyanalyzer/.
"""

import copy

from ai import changes

from . import common, intel, prioritize, review


def _inventory_cves():
    doc = prioritize.load_exposure() or {}
    return sorted({c['id'] for p in (doc.get('vulns') or {}).get('packages') or []
                   for c in p.get('cves') or [] if common.CVE_RE.match(c.get('id') or '')})


@changes.register
class VulnsIntelUpdate(changes.ChangeAction):
    name = 'vulns_intel_update'
    description = 'Vulnerabilities: download CISA KEV / FIRST EPSS into the local cache (only CVE ids are sent)'

    def parse_args(self, args):
        which = (args[0] if args else 'all') or 'all'
        if which not in ('kev', 'epss', 'all'):
            raise ValueError('choose kev, epss or all')
        return {'which': which}

    def plan(self, which):
        result = intel.plan_update(which, _inventory_cves())
        result['args'] = {'which': which}
        return result

    def apply(self, which, get=None):
        result = intel.apply_update(which, _inventory_cves(), get=get)
        result['args'] = {'which': which}
        return result

    def revert_plan(self, entry):
        files = (entry.get('state') or {}).get('files') or {}
        steps = [{'description': ('Restore the previous %s' % path) if backup else ('Remove %s' % path),
                  'command': 'mv %s.previous %s' % (path, path) if backup else 'rm %s' % path,
                  'effect': 'the cache returns to the state before the update'} for path, backup in files.items()]
        return {'status': 'ok', 'steps': steps, 'risk': 'low' if steps else 'none', 'warnings': [], 'revert': []}

    def revert_apply(self, entry):
        return intel.revert_update(entry)


def _changed_priorities(before, after, package):
    old = {i['cve']: i['priority'] for i in before.get('items') or [] if i['package'] == package}
    new = {i['cve']: i['priority'] for i in after.get('items') or [] if i['package'] == package}
    return [{'cve': cve, 'before': old.get(cve), 'after': new.get(cve)} for cve in sorted(set(old) | set(new))
            if old.get(cve) != new.get(cve)]


@changes.register
class VulnsReviewDecide(changes.ChangeAction):
    name = 'vulns_review_decide'
    description = 'Vulnerabilities: decision on an item of the review queue (map, none, ignore, finding)'

    def parse_args(self, args):
        args = list(args) + ['', '', '']
        if not common.REVIEW_ID_RE.match(args[0]):
            raise ValueError('invalid review item id')
        token = args[1].strip()
        if token == 'clear':
            decision, target, days = 'clear', None, None
        else:
            decision, target, days = review.parse_decision(token)
        return {'item_id': args[0], 'decision': decision, 'target': target, 'days': days,
                'comment': common.decode_comment(args[2] or '-')}

    def _context(self, item_id):
        doc = prioritize.load_exposure()
        state = review.load_state()
        before = prioritize.build(doc, state=state)
        item = next((q for q in before.get('review') or [] if q['id'] == item_id), None)
        if item is None:
            raise ValueError('review item not found (the inventory may have changed)')
        return doc, state, before, item

    def _new_state(self, state, item, decision, target, days, comment):
        new = copy.deepcopy(state)
        if decision == 'clear':
            new['decisions'].pop(item['id'], None)
            return new, None
        if decision == 'map' and target not in {c['id'] for c in item['candidates']}:
            raise ValueError('the service is not one of the candidates of this item')
        if decision == 'map' and not item.get('package'):
            raise ValueError('only package items can be mapped to a service')
        record = {'decision': decision, 'target': target, 'package': item.get('package'), 'kind': item['kind'],
                  'subject': item['subject'], 'comment': comment, 'ts': common.iso(),
                  'until': common.iso(common.now() + days * 86400) if days else None}
        new['decisions'][item['id']] = record
        return new, record

    def plan(self, item_id, decision, target, days, comment):
        doc, state, before, item = self._context(item_id)
        new, record = self._new_state(state, item, decision, target, days, comment)
        after = prioritize.build(doc, state=new)
        changed = _changed_priorities(before, after, item.get('package')) if item.get('package') else []
        cand = next((c for c in item['candidates'] if c['id'] == target), {})
        label = '%s %s/%s' % (cand.get('name') or cand.get('service'), cand.get('proto'), cand.get('port')) \
            if cand else target
        what = {'map': 'treat %s as part of service %s' % (item['subject'], label),
                'none': 'confirm that %s has no network path (library only)' % item['subject'],
                'ignore': 'hide %s from the queue for %s days' % (item['subject'], days),
                'finding': 'confirm %s as a real finding' % item['subject'],
                'clear': 'remove the decision on %s (back to pending)' % item['subject']}[decision]
        info = [{'title': 'Effect on the priorities',
                 'items': ['%s: %s -> %s' % (c['cve'], c['before'] or '-', c['after'] or '-') for c in changed] or
                 ['no priority changes']}]
        if item.get('ai_suggestion'):
            info.append({'title': 'AI suggestion (advice only)',
                         'items': ['mapping: %s' % item['ai_suggestion'].get('mapping'),
                                   (item['ai_suggestion'].get('text') or '')[:400]]})
        return {'status': 'ok', 'risk': 'low',
                'steps': [{'description': what[0].upper() + what[1:],
                           'command': 'write %s (decision of item %s)' % (common.paths()['review'], item_id),
                           'effect': 'priorities and lists are recomputed; the firewall is not changed'}],
                'warnings': [] if item['status'] == 'pending' or decision == 'clear' else
                ['this item already has a decision; it is replaced'],
                'revert': ['Undo restores the previous decision of this item.'], 'info': info,
                'changes': changed, 'record': record, 'args': {'item_id': item_id, 'decision': decision,
                                                                'target': target, 'days': days}}

    def apply(self, item_id, decision, target, days, comment):
        _doc, state, _before, item = self._context(item_id)
        previous = state['decisions'].get(item_id)
        new, record = self._new_state(state, item, decision, target, days, comment)
        review.save_state(new)
        return {'status': 'ok', 'done': True, 'steps': [], 'args': {'item_id': item_id, 'decision': decision,
                                                                    'target': target, 'days': days},
                'completed': ['decision "%s" stored for %s' % (decision, item['subject'])],
                'state': {'item_id': item_id, 'previous': previous, 'record': record}}

    def revert_plan(self, entry):
        st = entry.get('state') or {}
        return {'status': 'ok', 'risk': 'low', 'warnings': [], 'revert': [],
                'steps': [{'description': 'Restore the previous decision of review item %s' % st.get('item_id'),
                           'command': 'write %s' % common.paths()['review'],
                           'effect': 'previous decision: %s' % ((st.get('previous') or {}).get('decision') or
                                                                'none (pending)')}]}

    def revert_apply(self, entry):
        st = entry.get('state') or {}
        state = review.load_state()
        if st.get('previous'):
            state['decisions'][st['item_id']] = st['previous']
        else:
            state['decisions'].pop(st.get('item_id'), None)
        review.save_state(state)
        return {'status': 'ok', 'done': True, 'steps': [], 'completed': ['previous decision restored']}
