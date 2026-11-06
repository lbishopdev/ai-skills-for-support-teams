"""Optional real-LLM adapter. DISABLED BY DEFAULT and contains no network code.

Nothing in the demo, the tests or the quickstart needs this file. It exists to show
where a real model would plug in: it must implement the same `generate(task)`
interface and would receive the same allow-listed, scrubbed data as the mock.

To use a real model you would write the provider call yourself, in an environment
you have approved, with credentials from your own secret store. This repository
never reads, stores or asks for API keys.
"""

from __future__ import annotations

import os

from .model import ModelTask, build_prompt


class AdapterDisabled(RuntimeError):
    pass


class LLMAdapter:
    ENABLE_VAR = "SCOPEGUARD_ENABLE_LLM"

    def generate(self, task: ModelTask) -> str:
        if os.environ.get(self.ENABLE_VAR) != "1":
            raise AdapterDisabled(f"LLM adapter is disabled (set {self.ENABLE_VAR}=1 to enable)")
        _prompt = build_prompt(task)  # what would be sent; fenced and labelled as untrusted
        raise NotImplementedError("No provider is wired up in this demo. Bring your own.")
