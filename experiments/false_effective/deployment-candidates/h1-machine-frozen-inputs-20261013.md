# H1 machine-frozen input candidate — 2026-10-13

This packet fills only facts that can be reproduced from source trees and the
currently allocated machine. It remains **unregistered**, is not a formal H1
start, and supplies none of the independent command, activation-path,
producer, observer, or cross-arm reviews required for admission.

## Frozen source and environment candidates

| Component | Commit | Tree or byte digest |
| --- | --- | --- |
| vLLM-HUST | `b093ae0096a4ee801064f7a3673d42383e89f5c7` | tree `dd66f7b4b1844a19211894706786832aef63d5ff` |
| vLLM-Ascend-HUST | `fd70a5c818363ee4357604e637e36fb52860ccca` | tree `40760a184f20adbc9b7993f72940028ec229626c` |
| Extension Manager wheel source | `52922dec6b67db1825404d0bfd0d68305f6dcfd1` | tree `eaa9df581a01e8c1c734105612bdd8fd1cbb88b7`; wheel SHA-256 `2e0ab6c766fe875f518be309123fb4571cd6737559c6bd7948d7074d04ddb382` |
| KV MOD | `9728ccd9df68c654aaf541bb7565c0bd3f85b983` | tree `ea6911c6e0b8a0d7ff66d3078397dd4c615a3364` |
| installed venv bytes | 196 distributions; `uv pip check` passed | `sha256:9aabf5ce2e4022724770ab56f75ded0c1005e82994ae5c70b8abd7186ddb6013` |
| container image | `192.168.0.6:5050/vllm-ascend-ssh:v1` | Kubernetes pod-status image ID `sha256:cd3c36c1832d8b9dfd193405d52a73b22ca2699fbe95271015bc7932bef3e2ee` |

The venv digest covers installed venv bytes only. It excludes CANN, driver,
model and host OS. A full `pip check` that also exposes CANN's external Python
path is not clean, so this packet does not claim whole-stack dependency
consistency.

The Host/Ascend pair has a bounded Qwen2.5 eager TP2 contract subset result of
175 passed and 1 skipped. The broader CPU suite stopped after 50 failures
(1985 passed and 12 skipped), concentrated outside the proposed profile. The
pair is therefore a narrow candidate, not a general compatibility claim.

## Model, workload, fault and hardware

All 14 files in `qwen2.5-7b-instruct-a09a3545.sha256` were re-read and matched
on this allocation. The manifest SHA-256 is
`8075871e293fffe8c042b5ce165997a1b8f4487cad1e570168285279b4a19fd9`.
The canonical request is `h1-qwen2.5-7b-workload.json`, SHA-256
`9ff24793404386289eb61866b57f6943914af8f46317af28dc60c279e777198d`.

The v2 fault descriptor is
`h1-partial-worker-coverage-fault.json`, SHA-256
`83cf593eda175a7a8c809350a6456bb1070bcba25e3b341c9c6598db16d46a17`.
It freezes logical worker ordinal 0 for the current host and deliberately has
no process epoch. The formal runner must resolve the epoch after launch from
the host-owned process snapshot.

The current allocation exposes two healthy Ascend 910B2 devices as physical
IDs 3 and 6, with no NPU processes at capture time. The proposed topology is a
single-host TP2 eager cold start. Physical IDs are allocation-local and must be
rechecked immediately before every start.

## Remaining admission blockers

- The Host and MOD commits remain local candidates and are not repository
  reachable through the current GitHub App installation.
- The exact Host/Ascend tuple has not received a bounded support-matrix
  qualification.
- `verified-adapters.json` remains empty; arm and lifecycle-source commands are
  not registered.
- Independent command, activation-path, observer, cross-arm and retention
  reviews remain false.

The deployment registration therefore stays `unregistered`, the study stays
`pre-admission`, and H1 remains 0/9.
