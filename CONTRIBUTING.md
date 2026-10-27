# Contributing

logsieve is a local log reader. Pull requests should stay inside that job.

## What belongs here

- A parser that turns one more log shape into the same timeline.
- A pattern for an error code you can point at a public page.
- A redaction gap, with a fictional fixture that shows the identifier surviving today and disappearing after the change.

## What does not

- Real logs, tenant names, hostnames, or screenshots of a production console.
- A change that sends log text anywhere other than the optional model URL the operator passed.
- A remediation action. The tool suggests checks. It does not change the endpoint.

## Adding a pattern

Put a YAML file in `src/logsieve/patterns/library/` or pass it with `--pattern-dir`. Each entry needs:

- `id` and `title`
- `codes`, `signatures`, `constant`, or `event_ids` (a provider plus an id)
- `self_test`: a fictional line the matcher must hit. For an event id, also set `self_test_provider` and `self_test_event_id`
- `sources`: one or more `https://` URLs
- `confidence`: `high`, `medium`, or `low`
- `uncertain: true` when the public source gives more than one meaning, or when the source is a sample rather than a reference
- `explanation` in your own words, and `fix_hints` that are checks, not scripts
- `category` and, when this code is often a symptom of another category, `symptom_of`

`category: generic` and event-id-only entries are notes. They do not become the suspected cause when a specific code also matched.

Run `python -m pytest` from a virtualenv that has installed the project with `pip install -e ".[dev]"`.

## License

By contributing, you agree that your changes are MIT, copyright Wasaf Abbasi, the same as the rest of the tree.