# Virtual networking result format

The virtual-networking harness writes a stable artifact shape for orchestrated scenarios and compact per-probe bundles.

## Artifact layout

Each run writes:

```text
artifacts/<run-id>/
  summary.json
  summary.txt
  events.jsonl
  run-state.json
  captures/
```

If a run is repeated with the same `run_id`, the previous artifact directory is replaced. Run IDs are intentionally slug-like and cannot contain path separators, so replacement is confined to a child directory of the artifact root.

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

Common capture examples now include:

- actor logs such as `captures/actors/listener.log`
- fixture configs/logs such as `captures/fixtures/miniupnpd-edge-router/configfile.conf`
- combined namespace snapshots such as `captures/setup-namespace-snapshot.txt`

Probe-specific result bundles may also appear under `captures/probes/<step-name>/` inside a scenario run. Probe captures are written directly in that directory; probe outputs are recorded in top-level `run-state.json`.

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

## `run-state.json`

`run-state.json` is the machine-readable composition state for the run. It records:

- topology metadata
- resolved context values
- fixture outputs
- actor outputs
- probe outputs and result directories

This is the authoritative handoff format between fixtures, actors, probes, and future automation. It replaces separate actor/probe output files and copied scenario/topology definition artifacts.

## Current adoption

The shared result-writing path now lives in:

- `lib/tools/probe_runner.py`
- `lib/tools/probe_actions.py`
- `lib/reporting/result_recorder.py`
- `lib/reporting/result_summary.py`

`run.py` writes scenario results in-process. `probe_sequence` probes run through `lib/tools/probe_runner.py` with typed actions from `lib/tools/probe_actions.py`.
