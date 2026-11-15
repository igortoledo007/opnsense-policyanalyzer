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

namespace OPNsense\PolicyAnalyzer;

/**
 * Translator handed to the plugin's Volt views as "lang": lang._('...') looks in the plugin catalogue first and
 * delegates to the core translator (XSS-safe escaping, %name% placeholders, core catalogue) for everything else.
 */
class ViewTranslator
{
    private $core;

    public function __construct($core)
    {
        $this->core = $core;
    }

    public function _($translateKey, array $placeholders = []): string
    {
        $own = L10n::t($translateKey);
        if ($own === $translateKey || $own === gettext($translateKey)) {
            return $this->core->_($translateKey, $placeholders);
        }
        foreach ($placeholders as $key => $value) {
            $own = str_replace('%' . $key . '%', (string)$value, $own);
        }
        return view_html_safe($own);
    }

    public function __call($name, $args)
    {
        return $this->core->$name(...$args);
    }
}
