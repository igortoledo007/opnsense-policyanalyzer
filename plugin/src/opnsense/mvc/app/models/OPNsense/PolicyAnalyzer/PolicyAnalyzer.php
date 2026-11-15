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

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;

/**
 * Policy Analyzer settings: the analysis itself has no settings yet, the model holds the optional AI layer.
 * Provider specific checks live in validateProvider<Name>() so a new provider only adds its own method.
 */
class PolicyAnalyzer extends BaseModel
{
    /** paths that may never hold model files */
    private const FORBIDDEN_DIRS = ['/dev', '/proc', '/tmp', '/var/tmp', '/conf', '/boot'];

    /**
     * {@inheritdoc}
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        $provider = (string)$this->ai->provider;

        if (!empty((string)$this->ai->enabled) && $provider == 'none') {
            $messages->appendMessage(new Message(\OPNsense\PolicyAnalyzer\L10n::t('Select a provider to enable AI assistance.'), 'ai.provider'));
        }

        $dir = (string)$this->ollama->models_dir;
        if ($dir !== '') {
            $parts = explode('/', $dir);
            $forbidden = false;
            foreach (self::FORBIDDEN_DIRS as $prefix) {
                if ($dir == $prefix || strpos($dir, $prefix . '/') === 0) {
                    $forbidden = true;
                }
            }
            if (in_array('..', $parts) || strpos($dir, '//') !== false || $dir == '/' || $forbidden) {
                $messages->appendMessage(new Message(
                    \OPNsense\PolicyAnalyzer\L10n::t('Choose a dedicated directory on a local filesystem, for example /var/db/ai/models.'),
                    'ollama.models_dir'
                ));
            }
        }

        if ($provider == 'claudecode') {
            /* the bridge address is needed even before the AI is enabled (Test connection, List models) */
            $this->validateBridgeUrl($messages);
        }

        $method = 'validateProvider' . ucfirst($provider);
        if (!empty((string)$this->ai->enabled) && method_exists($this, $method)) {
            $this->$method($messages);
        }
        return $messages;
    }

    private function validateProviderOllama($messages)
    {
        if ((string)$this->ollama->location == 'lan' && (string)$this->ollama->url == '') {
            $messages->appendMessage(new Message(\OPNsense\PolicyAnalyzer\L10n::t('Enter the URL of the Ollama server.'), 'ollama.url'));
        }
        if ((string)$this->ollama->model == '') {
            $messages->appendMessage(new Message(\OPNsense\PolicyAnalyzer\L10n::t('Select or enter a model.'), 'ollama.model'));
        }
    }

    private function validateProviderClaude($messages)
    {
        /* UpdateOnlyTextField hides its value from __toString(), getValue() holds the stored key */
        if ($this->claude->apikey->getValue() == '') {
            $messages->appendMessage(new Message(\OPNsense\PolicyAnalyzer\L10n::t('Enter an Anthropic API key.'), 'claude.apikey'));
        }
    }

    /**
     * Claude Code (LAN): plain http(s)://host[:port] of the claude-bridge, like the Ollama LAN URL
     * (no credentials, query or fragment: the token travels in the Authorization header only)
     */
    private function validateBridgeUrl($messages)
    {
        $url = (string)$this->claudecode->url;
        if ($url == '') {
            $messages->appendMessage(new Message(
                \OPNsense\PolicyAnalyzer\L10n::t('Enter the URL of the Claude Code bridge, for example http://bridge.example.lan:11436.'),
                'claudecode.url'
            ));
            return;
        }
        $parts = parse_url($url);
        if (
            $parts === false || !in_array(strtolower($parts['scheme'] ?? ''), ['http', 'https']) ||
            empty($parts['host']) || isset($parts['user']) || isset($parts['pass']) ||
            isset($parts['query']) || isset($parts['fragment'])
        ) {
            $messages->appendMessage(new Message(
                \OPNsense\PolicyAnalyzer\L10n::t('Use http(s)://host[:port] without credentials, query or fragment.'),
                'claudecode.url'
            ));
        }
    }

    private function validateProviderClaudecode($messages)
    {
        /* UpdateOnlyTextField hides its value from __toString(), getValue() holds the stored token */
        if ($this->claudecode->token->getValue() == '') {
            $messages->appendMessage(new Message(\OPNsense\PolicyAnalyzer\L10n::t('Enter the token of the Claude Code bridge.'), 'claudecode.token'));
        }
    }
}
