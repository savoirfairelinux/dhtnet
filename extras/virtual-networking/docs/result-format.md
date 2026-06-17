# Virtual networking result format

The virtual-networking harness writes a stable artifact shape for both orchestrated scenarios and per-probe result bundles.

## Artifact layout

Each run writes:

```text
artifacts/<run-id>/
  summary.json
  summary.txt
  events.jsonl
  captures/
  probes/
  .meta/
    assertions.jsonl
    captures.jsonl
    metrics.jsonl
    notes.jsonl
    fields.jsonl
    run-state.json
```

If a run is repeated with the same `run_id`, the previous artifact directory is replaced.

## `summary.json`

Top-level fields:

- `run_id`
- `scenario`
- `status`
  - one of `passed`, `failed`, `error`, `skipped`
- `started_at`
- `ended_at`
- `duration_s`
- `assertions`
- `metrics`
- `captures`
- `notes`

Optional top-level fields are copied from the run field stream and commonly include:

- `topology`
- `lab`
- `profile_before`
- `profile_after`

### Assertion records

Each assertion record contains:

- `name`
- `status`
- `duration_ms`
- `details`

### Capture records

Each capture record contains:

- `label`
- `kind`
- `path`

Typical capture kinds:

- `log`
- `command-output`
- `pcap`
- `state-dump`
- `summary`
- `scenario-definition`

Common capture examples now include:

- actor logs such as `captures/actors/listener.log`
- actor output JSON such as `captures/actors/listener-output.json`
- fixture configs/logs such as `captures/fixtures/miniupnpd-edge-router/configfile.conf`
- copied probe summaries such as `captures/probe-summary.json`

Probe-specific result bundles may also appear under `probes/<step-name>/` inside a scenario run. Those bundles reuse the same summary/assertion format without creating a second top-level run directory.

## `summary.txt`

`summary.txt` is the user-facing scan-friendly view. It always shows:

- scenario name
- run identifier
- overall status
- start time, end time, and total duration
- assertions with status and duration
- metrics
- capture count
- full capture directory path
- notes

## `events.jsonl`

`events.jsonl` is append-only and intended for detailed timelines. Each line is a JSON object with:

- `timestamp`
- `event`
- `status`
- `message`

## `.meta/run-state.json`

`run-state.json` is the machine-readable composition state for the run. It records:

- topology metadata
- resolved context values
- fixture outputs
- actor outputs
- probe outputs and result directories

This is the authoritative handoff format between fixtures, actors, probes, and future automation.

## Current adoption

The shared result-writing path now lives in:

- `lib/probe_runner.py`
- `lib/runner/result_recorder.py`
- `lib/result_summary.py`

`run.py` writes scenario results in-process. `probe_sequence` probes run through `lib/probe_runner.py`.
