# Security

logsieve reads logs you point it at and writes a report and, if you ask, an encrypted mapping. It does not change the endpoint and it does not phone home.

## What it protects

The report and the optional model payload are built from redacted text. Hostnames, accounts, SIDs, addresses, GUIDs, domain names, and user-profile paths are replaced with stable tokens. Before a payload is printed or sent, logsieve checks that those original identifiers are not still visible. If one is, it refuses and does not print the identifier.

The mapping file is Fernet ciphertext. With `LOGSIEVE_VAULT_PASSPHRASE` set, the key is derived with PBKDF2-HMAC-SHA256 (200,000 iterations). Otherwise a key file is written next to the vault and restricted to the owner on POSIX. The passphrase is read from the environment, not from the argument list.

## What it does not protect

Redaction is a set of patterns. A bare account name that never appears in a path, an email, a `DOMAIN\user` pair, a user field, or `--username` can remain. A secret that is not written as `password=...` (or one of the other assignments the scanner knows) can remain. Treat both as best effort.

The vault key is the decryption key. Anyone who can read the key file, or who knows the passphrase, can reverse the report. Keep the key next to the vault only on a machine you control. Do not commit either file, and do not paste them into a ticket.

PBKDF2 is not memory-hard. A long passphrase matters more than the iteration count if you do not use a key file.

`--no-redact` leaves identifiers in the report and refuses `--llm` and `--show-payload`. Do not pass that flag and then paste the report into a hosted model.

The model URL is whatever you pass to `--llm`. logsieve sends only the redacted payload, after the leak check. The operator of that URL still receives that text. A local Ollama endpoint is the default. An API key, if you set `LOGSIEVE_LLM_API_KEY`, is sent only as a bearer header and is not written into the report.

The suspected cause is a hint from a partial library. It is not a finding you should treat as proof.

## Reporting a problem

Open an issue on the repository that hosts this project. Please use fictional log lines. Do not include a vault, a key file, or a real client log.