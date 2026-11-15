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

    Reusable AI layer for OPNsense plugins (read only, opt-in).

    Components:
        config      AIConfig, provider settings read from config.xml
        providers   registry of model endpoints (Ollama, Claude), stdlib urllib only
        changes     generic plan/apply/revert runner for changes to the system
        journal     undo journal of applied changes
        storage     local model storage probe and preparation
        anonymizer  reversible placeholder substitution
        prompts     shared guardrail system prompt + language mapping
        audit       JSON lines audit log with hashes and sizes
        assistant   Assistant/Task, the facade consumers call
        scenarios   catalog of the AI scenarios and the per scenario routing (provider, limits, sync/queue)
        validate    answer checks, language heuristic, <think> removal
        jobqueue    background queue of AI jobs (SQLite) and the answer cache
        mapreduce   batches + consolidation for data above the budget of a route

    Nothing in this package writes configuration or calls the OPNsense API:
    it only turns data into explanatory text.
"""

from .anonymizer import Anonymizer, StreamRestorer
from .assistant import AIDisabled, AnswerRejected, Assistant, Task, is_queued
from .audit import AuditLog
from .config import AIConfig
from .providers import ProviderError, ProviderRefusal, get_provider

__all__ = [
    'AIConfig', 'AIDisabled', 'Anonymizer', 'AnswerRejected', 'Assistant', 'AuditLog', 'ProviderError', 'ProviderRefusal',
    'StreamRestorer', 'Task', 'is_queued',
    'get_provider',
]
