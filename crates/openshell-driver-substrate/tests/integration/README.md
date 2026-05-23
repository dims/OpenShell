# OpenShell-on-Substrate feature observation suite

Standalone harness used to walk through the supervisor's value-add
features (HTTP proxy, OPA/Rego policy, OCSF audit, Landlock,
checkpoint/restore preservation) end-to-end inside a Substrate gVisor
actor. The four live integration tests next door only exercise the
driver-side lifecycle; this harness exercises the supervisor side.

## Layout

| Path | Purpose |
|---|---|
| `Dockerfile` | Builds a feature-test supervisor image on top of the M0 image, swapping in the substrate-aware wrapper + a richer baked policy + a workload script. |
| `data.yaml` | Test policy: empty M0 default is replaced with a deny-by-default plus one allow rule (`example.com`) and one denied path so the OPA engine is exercised. |
| `test-workload.sh` | Workload command line; runs probes (fs read/write, proxy CONNECT, direct egress, log inspection) and prints `[oshl-test] <key>: <value>` lines to stderr. |
| `actor-template.yaml` | Pre-provisioned `ActorTemplate` referencing the test image + invoking `test-workload.sh`. |
| `build-image.sh` | Build + push helper. Runs on a Linux host with cargo + docker + access to the kind-registry. |
| `run.sh` | End-to-end harness: applies the template, spawns an actor, waits, dumps `kubectl logs` filtered for `[oshl-test]`, suspends + deletes. |

## Findings register

Per-test status lands in `~/notes/2026-05-23-openshell-features-findings.md`.
