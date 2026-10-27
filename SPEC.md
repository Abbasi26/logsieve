# Original task specification (from cloud agent transcript)

Build v0.1 of **logsieve**, a local-first, privacy-preserving log diagnosis tool for Windows endpoint admins. Follow ALL rules in uploads/gemeinsame_regeln.md. The prior-art research is in uploads/stand_der_technik.md (section C): Presidio does generic reversible pseudonymization, k8sgpt and HolmesGPT target Kubernetes, and CMTrace Open only displays logs. The gap is MECM/ConfigMgr client logs, Intune Management Extension (IME) logs and Windows event logs, combining reversible pseudonymization, known-pattern detection and optional LLM explanation.

v0.1 scope (Python 3.11+ CLI):
- Parsers for:
  - CMTrace/ConfigMgr log format
  - IntuneManagementExtension.log / AgentExecutor.log
  - Windows EVTX (via python-evtx) and exported event XML/CSV
  - plain text and journald JSON
  - normalized into one timeline
- Reversible pseudonymization:
  - covers hostnames, UPNs/emails, SIDs, IPv4/IPv6, GUIDs (configurable), domain names and user paths
  - stable tokens per run
  - the mapping is stored locally in an encrypted file
  - a `reveal` command re-identifies an LLM answer
- Pattern library as YAML: known error codes and signatures (e.g. common MECM/IME/Windows Update/Win32 app install error codes) with explanation and fix hints. Only include codes you are confident about, with source links, and mark uncertain ones.
- `logsieve diagnose` produces a Markdown/HTML report:
  - timeline of errors
  - matched patterns
  - suspected root cause
  - next steps
- Optional LLM step, OFF by default. Prefer a local model (Ollama / any OpenAI-compatible URL). It only ever sends pseudonymized text, and a `--show-payload` dry run shows exactly what would be sent.
- `logsieve demo` with bundled fictional logs.
- pytest suite covering parsers, pseudonymization round-trip (no leaks: test that original identifiers never appear in the payload) and pattern matching.
