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
 * Translations of the plugin: its own gettext domain "PolicyAnalyzer"
 * (/usr/local/share/locale/<lang>/LC_MESSAGES/PolicyAnalyzer.mo), falling back to the core "OPNsense" domain,
 * so strings shared with the core keep the core translation and nothing in the core catalogue changes.
 * The locale is the one the core already selected for the request (ControllerRoot::setLang).
 */
class L10n
{
    const DOMAIN = 'PolicyAnalyzer';
    private static $bound = false;

    private static function bind()
    {
        if (!self::$bound) {
            bindtextdomain(self::DOMAIN, '/usr/local/share/locale');
            bind_textdomain_codeset(self::DOMAIN, 'UTF-8');
            self::$bound = true;
        }
    }

    /**
     * translate a message: plugin catalogue first, core catalogue second, the English text last
     * @param string $text English message (msgid)
     * @return string
     */
    public static function t($text)
    {
        self::bind();
        $out = dgettext(self::DOMAIN, $text);
        return $out !== $text ? $out : gettext($text);
    }
}
