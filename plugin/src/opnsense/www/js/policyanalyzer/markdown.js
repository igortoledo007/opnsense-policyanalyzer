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

/**
 * Small, safe Markdown renderer for AI answers (Policy Analyzer pages).
 *
 *   element.innerHTML = PAMarkdown.render(text);         returns an HTML string
 *   $(el).html(PAMarkdown.render(text, {citations: true}))
 *
 * Supported: # .. ###### headings, **bold**, __bold__, *italic*, _italic_, ~~strike~~, `code`, fenced code
 * blocks (```diff lines get +/- colours), - * + • and 1. lists (one nested level), > quotes, --- rules,
 * paragraphs with line breaks; evidence citations such as [filterlog: 14 blocks] become small badges.
 * Sanitization: the input is HTML-escaped before anything else and the renderer only ever emits its own fixed
 * tags with fixed class names. No raw HTML, no attributes taken from the text, no links: [text](url) is shown
 * as "text (url)" so an answer can never turn into a clickable phishing link. Tables are shown as preformatted
 * text. Styles: css/policyanalyzer/console.css (.pa-md).
 */
const PAMarkdown = (function () {
    'use strict';

    const CITE = /\[((?:filterlog(?:_top)?|rules?|path(?:_rules)?|hosts?|aliases|alias|quarantine|changes|suricata|findings?|exposure|event|alert|source_activity|log_hits|neighbours|evidence)(?:\s*[:\]][^\]\n]{0,160})?)\]/gi;

    function escape(value) {
        return String(value === undefined || value === null ? '' : value)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    /* inline formatting on already escaped text; code spans are cut out first so nothing inside them changes */
    function inline(text, opts) {
        const codes = [];
        let out = text.replace(/`([^`\n]+)`/g, function (m, code) {
            codes.push('<code>' + code + '</code>');
            return '\u0000' + (codes.length - 1) + '\u0000';
        });
        out = out.replace(/\[([^\]\n]{1,200})\]\(([^)\s]{1,300})\)/g, '$1 ($2)');
        if (opts.citations !== false) {
            out = out.replace(CITE, '<span class="pa-md-cite">$1</span>');
        }
        out = out.replace(/\*\*(?=\S)([^*\n]*?\S)\*\*/g, '<strong>$1</strong>');
        out = out.replace(/(^|[^\w])__(?=\S)([^_\n]*?\S)__(?![\w])/g, '$1<strong>$2</strong>');
        out = out.replace(/(^|[^\w*])\*(?=[^\s*])([^*\n]*?[^\s*])\*(?![\w*])/g, '$1<em>$2</em>');
        out = out.replace(/(^|[^\w])_(?=[^\s_])([^_\n]*?[^\s_])_(?![\w])/g, '$1<em>$2</em>');
        out = out.replace(/~~(?=\S)([^~\n]*?\S)~~/g, '<del>$1</del>');
        return out.replace(/\u0000(\d+)\u0000/g, function (m, idx) { return codes[+idx]; });
    }

    function codeBlock(lines, lang) {
        const isDiff = /^(diff|patch)$/i.test(lang || '');
        /* one block span per line: diff colours span the whole width without extra blank lines */
        const body = lines.map(function (line) {
            const safe = escape(line) || '\u200b';
            let cls = 'pa-md-line';
            if (isDiff && /^\+(?!\+\+)/.test(line)) {
                cls += ' pa-md-add';
            } else if (isDiff && /^-(?!--)/.test(line)) {
                cls += ' pa-md-del';
            } else if (isDiff && /^@@/.test(line)) {
                cls += ' pa-md-hunk';
            }
            return '<span class="' + cls + '">' + safe + '</span>';
        }).join('');
        const label = lang ? '<span class="pa-md-lang">' + escape(lang) + '</span>' : '';
        return '<pre class="pa-md-code' + (isDiff ? ' pa-md-diff' : '') + '">' + label + '<code>' + body +
            '</code></pre>';
    }

    function render(text, opts) {
        opts = opts || {};
        const lines = String(text === undefined || text === null ? '' : text).replace(/\r\n?/g, '\n').split('\n');
        const html = [];
        let para = [];
        let list = null;            // {type, items: [{html, sub: {type, items}}]}

        function flushPara() {
            if (para.length) {
                html.push('<p>' + para.map(function (l) { return inline(escape(l), opts); }).join('<br>') + '</p>');
                para = [];
            }
        }

        function renderList(l) {
            const tag = l.type === 'ol' ? 'ol' : 'ul';
            return '<' + tag + '>' + l.items.map(function (item) {
                return '<li>' + item.html + (item.sub ? renderList(item.sub) : '') + '</li>';
            }).join('') + '</' + tag + '>';
        }

        function flushList() {
            if (list) {
                html.push(renderList(list));
                list = null;
            }
        }

        let i = 0;
        while (i < lines.length) {
            const line = lines[i];
            const fence = line.match(/^\s*(```|~~~)\s*([\w+-]*)\s*$/);
            if (fence) {
                flushPara();
                flushList();
                const body = [];
                i++;
                while (i < lines.length && !new RegExp('^\\s*' + fence[1] + '\\s*$').test(lines[i])) {
                    body.push(lines[i]);
                    i++;
                }
                html.push(codeBlock(body, fence[2]));
                i++;
                continue;
            }
            if (/^\s*\|.*\|\s*$/.test(line)) {
                flushPara();
                flushList();
                const body = [];
                while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) {
                    body.push(lines[i].trim());
                    i++;
                }
                html.push(codeBlock(body, ''));
                continue;
            }
            const heading = line.match(/^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$/);
            if (heading) {
                flushPara();
                flushList();
                /* h4..h6 inside the answer, the page keeps its own h1..h3 */
                const level = Math.min(6, Math.max(4, heading[1].length + 2));
                html.push('<h' + level + ' class="pa-md-h">' + inline(escape(heading[2]), opts) + '</h' + level + '>');
                i++;
                continue;
            }
            if (/^\s{0,3}([-*_])(\s*\1){2,}\s*$/.test(line)) {
                flushPara();
                flushList();
                html.push('<hr>');
                i++;
                continue;
            }
            const quote = line.match(/^\s*>\s?(.*)$/);
            if (quote) {
                flushPara();
                flushList();
                const body = [];
                while (i < lines.length && /^\s*>/.test(lines[i])) {
                    body.push(lines[i].replace(/^\s*>\s?/, ''));
                    i++;
                }
                html.push('<blockquote>' + render(body.join('\n'), opts) + '</blockquote>');
                continue;
            }
            const item = line.match(/^(\s*)([-*+•]|\d{1,3}[.)])\s+(.*)$/);
            if (item) {
                flushPara();
                const nested = item[1].replace(/\t/g, '    ').length >= 2 && list && list.items.length;
                const type = /\d/.test(item[2]) ? 'ol' : 'ul';
                const entry = {html: inline(escape(item[3]), opts), sub: null};
                if (nested) {
                    const parent = list.items[list.items.length - 1];
                    if (!parent.sub) {
                        parent.sub = {type: type, items: []};
                    }
                    parent.sub.items.push(entry);
                } else {
                    if (list && list.type !== type) {
                        flushList();
                    }
                    if (!list) {
                        list = {type: type, items: []};
                    }
                    list.items.push(entry);
                }
                i++;
                continue;
            }
            if (/^\s*$/.test(line)) {
                flushPara();
                /* a blank line between items keeps the list open */
                if (list && i + 1 < lines.length && /^(\s*)([-*+•]|\d{1,3}[.)])\s+/.test(lines[i + 1])) {
                    i++;
                    continue;
                }
                flushList();
                i++;
                continue;
            }
            if (list && /^\s{2,}\S/.test(line)) {
                /* continuation of the last list item */
                const last = list.items[list.items.length - 1];
                last.html += '<br>' + inline(escape(line.trim()), opts);
                i++;
                continue;
            }
            flushList();
            para.push(line.trim());
            i++;
        }
        flushPara();
        flushList();
        return '<div class="pa-md">' + html.join('') + '</div>';
    }

    /* plain text of a rendered answer (copy button) */
    function toText(text) {
        return String(text || '');
    }

    return {render: render, escape: escape, inline: function (t) { return inline(escape(t), {}); }, toText: toText};
})();

if (typeof module !== 'undefined' && module.exports) {
    module.exports = PAMarkdown;
}

window.PAMarkdown = PAMarkdown;
