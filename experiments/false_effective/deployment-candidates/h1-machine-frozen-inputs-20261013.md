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
| Extension Manager wheel source | `9f075f8e70da574fb90bdd392cf7c7e424c75972` | tree `91ebc43a7a82bbc561ad3ed9f94bd02ac72c2a12`; wheel SHA-256 `ec7d718a92361f77da53095547ae3ab407eabce9d471e6cc2e5f859bb69173da` |
| KV MOD | `9728ccd9df68c654aaf541bb7565c0bd3f85b983` | tree `ea6911c6e0b8a0d7ff66d3078397dd4c615a3364` |
| installed venv bytes | 196 distributions; `uv pip check` passed | `sha256:52cdc8b6356c57899c15bf1aa3e0dafeeac3192eb71a8fab4d72c90d59335aa0` |
| container image | `192.168.0.6:5050/vllm-ascend-ssh:v1` | Kubernetes pod-status image ID `sha256:cd3c36c1832d8b9dfd193405d52a73b22ca2699fbe95271015bc7932bef3e2ee` |

The venv digest covers installed venv bytes only. It excludes CANN, driver,
model and host OS. A full `pip check` that also exposes CANN's external Python
path is not clean, so this packet does not claim whole-stack dependency
consistency.

The merged Manager installs the production `ecpa-formal-observer` command. A real TP2 preflight on the allocated 910B2 pair reached health 200 and a non-empty completion, froze both host-assigned worker epochs, quarantined worker ordinal 0, and ran the production observer while the service remained live. The observer retained the real runtime-effective claim, identified only worker ordinal 1, and computed coverage 0.5. Cleanup removed every owned process and NPU process. Result SHA-256 is `ed78d28566ba99a8e83468da3e0f37d2f982f34c09245553155ef3f7bf8119f2`; observer-result SHA-256 is `7f8afdbf894132922dd0990d541e3945ab44647ca4810e6283744794a3290455`. This remains an unregistered functional preflight and contributes zero formal H1 starts.

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
