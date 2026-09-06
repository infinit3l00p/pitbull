"""Cerberus — LLM-Guided Zero-Day Discovery Engine.

Academic basis:
- LLAMAFUZZ (arXiv:2406.07714): LLM enhances greybox fuzzing by guiding input mutations
- VulnLLM-R (arXiv:2512.07533): Specialized reasoning LLM for vulnerability detection
- DARPA AIxCC "All You Need Is A Fuzzing Brain" (arXiv:2509.07225): automated vuln detection + patching
- ELFuzz (arXiv:2506.10323): LLM synthesizes fuzzing strategies at meta-level
- Hybrid Fuzzing with LLM-Guided Input Mutation (arXiv:2511.03995): LLM semantics + traditional fuzzing

DEFENSIVE RESEARCH ONLY — discovery and reporting, no weaponization.
"""

from __future__ import annotations

from app.cerberus.target_analyzer import TargetAnalyzer
from app.cerberus.llm_fuzzer import LLMFuzzer
from app.cerberus.crash_triage import CrashTriage
from app.cerberus.vuln_library import VulnLibrary

__all__ = [
    "TargetAnalyzer",
    "LLMFuzzer",
    "CrashTriage",
    "VulnLibrary",
]
from app.cerberus.vuln_library import VulnLibrary

def init_neo4j_schema() -> None:
    """Initialize Neo4j schema for Cerberus."""
    _vl = VulnLibrary()
    _vl.init_schema()
